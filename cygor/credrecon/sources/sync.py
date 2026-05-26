"""
Credential Sync Engine
======================

Manages synchronization of credentials from all external sources.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .base import CredentialSource, FetchResult
from .cache import CredentialCache, get_cache
from .defaultcreds import DefaultCredsSource
from .cirt import CIRTSource
from ..credentials.schema import Credential

logger = logging.getLogger("credrecon.sources.sync")


@dataclass
class SyncResult:
    """Result of a sync operation."""
    success: bool
    sources_synced: List[str] = field(default_factory=list)
    sources_failed: List[str] = field(default_factory=list)
    total_credentials: int = 0
    sync_time: Optional[datetime] = None
    errors: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if self.sync_time is None:
            self.sync_time = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "sources_synced": self.sources_synced,
            "sources_failed": self.sources_failed,
            "total_credentials": self.total_credentials,
            "sync_time": self.sync_time.isoformat() if self.sync_time else None,
            "errors": self.errors,
        }


class CredentialSyncEngine:
    """
    Coordinates syncing credentials from multiple external sources.

    Provides:
    - Sync all sources
    - Sync specific sources
    - Get sync status
    - Manage cache
    """

    # Available sources
    AVAILABLE_SOURCES = ["defaultcreds", "cirt"]

    def __init__(self, cache: CredentialCache = None):
        """
        Initialize the sync engine.

        Args:
            cache: Shared credential cache
        """
        self.cache = cache or get_cache()
        self._sources: Dict[str, CredentialSource] = {}
        self._last_sync: Optional[SyncResult] = None

    def _get_source(self, name: str) -> Optional[CredentialSource]:
        """Get or create a source by name."""
        if name in self._sources:
            return self._sources[name]

        if name == "defaultcreds":
            self._sources[name] = DefaultCredsSource(cache=self.cache)
        elif name == "cirt":
            self._sources[name] = CIRTSource(cache=self.cache)
        else:
            return None

        return self._sources[name]

    def sync_all(self, force: bool = False) -> SyncResult:
        """
        Sync credentials from all available sources.

        Args:
            force: Force refresh even if cache is valid

        Returns:
            SyncResult with summary
        """
        return self.sync_sources(self.AVAILABLE_SOURCES, force=force)

    def sync_sources(
        self,
        sources: List[str],
        force: bool = False,
    ) -> SyncResult:
        """
        Sync credentials from specified sources.

        Args:
            sources: List of source names to sync
            force: Force refresh even if cache is valid

        Returns:
            SyncResult with summary
        """
        result = SyncResult(success=True)
        total_creds = 0

        for source_name in sources:
            source = self._get_source(source_name)
            if source is None:
                logger.warning(f"Unknown source: {source_name}")
                result.sources_failed.append(source_name)
                result.errors[source_name] = "Unknown source"
                continue

            try:
                logger.info(f"Syncing credentials from {source_name}...")
                fetch_result = source.fetch(force=force)

                if fetch_result.success:
                    result.sources_synced.append(source_name)
                    total_creds += len(fetch_result.credentials)
                    logger.info(
                        f"Synced {len(fetch_result.credentials)} credentials from {source_name}"
                    )
                else:
                    result.sources_failed.append(source_name)
                    result.errors[source_name] = fetch_result.error_message or "Unknown error"
                    logger.error(f"Failed to sync {source_name}: {fetch_result.error_message}")

            except Exception as e:
                result.sources_failed.append(source_name)
                result.errors[source_name] = str(e)
                logger.error(f"Exception syncing {source_name}: {e}")

        result.total_credentials = total_creds
        result.success = len(result.sources_failed) == 0

        self._last_sync = result
        return result

    def sync_source(self, source_name: str, force: bool = False) -> FetchResult:
        """
        Sync a single source.

        Args:
            source_name: Name of the source to sync
            force: Force refresh even if cache is valid

        Returns:
            FetchResult from the source
        """
        source = self._get_source(source_name)
        if source is None:
            return FetchResult(
                success=False,
                source_name=source_name,
                error_message=f"Unknown source: {source_name}",
            )

        return source.fetch(force=force)

    def get_last_sync(self) -> Optional[SyncResult]:
        """Get the result of the last sync operation."""
        return self._last_sync

    def get_cached_credentials(self) -> List[Credential]:
        """Get all cached external credentials."""
        return self.cache.get_cached_credentials()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    def invalidate_cache(self, source_name: str = None) -> int:
        """
        Invalidate cached credentials.

        Args:
            source_name: Source to invalidate (all if None)

        Returns:
            Number of entries invalidated
        """
        return self.cache.invalidate(source_name)

    def get_sync_status(self) -> Dict[str, Any]:
        """
        Get current sync status for all sources.

        Returns:
            Dictionary with status for each source
        """
        status = {}

        for source_name in self.AVAILABLE_SOURCES:
            cached = self.cache.get(source_name)
            status[source_name] = {
                "cached": cached is not None,
                "fetched_at": cached.fetched_at if cached else None,
                "expires_at": cached.expires_at if cached else None,
                "credential_count": len(cached.credentials) if cached else 0,
                "is_expired": cached.is_expired() if cached else True,
            }

        return status


def create_sync_engine(cache: CredentialCache = None) -> CredentialSyncEngine:
    """Factory function to create sync engine."""
    return CredentialSyncEngine(cache=cache)


def sync_all_sources(force: bool = False) -> SyncResult:
    """Convenience function to sync all sources."""
    engine = CredentialSyncEngine()
    return engine.sync_all(force=force)


def sync_source(source_name: str, force: bool = False) -> FetchResult:
    """Convenience function to sync a single source."""
    engine = CredentialSyncEngine()
    return engine.sync_source(source_name, force=force)
