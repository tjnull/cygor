"""
External Credential Sources
===========================

Framework for fetching and syncing credentials from external sources:
- DefaultCreds-cheat-sheet (GitHub)
- CIRT.net default passwords

Each source is implemented as a class that can:
- Fetch credentials from the remote source
- Parse and normalize to our Credential format
- Cache results locally for offline use
"""

from .base import CredentialSource, SourceConfig, FetchResult
from .cache import CredentialCache, CacheConfig
from .sync import CredentialSyncEngine

__all__ = [
    "CredentialSource",
    "SourceConfig",
    "FetchResult",
    "CredentialCache",
    "CacheConfig",
    "CredentialSyncEngine",
]
