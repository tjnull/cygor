"""
Cygor CredRecon Credentials Module
==================================

Hierarchical credential database with support for:
- Vendor/product-specific credentials
- Priority-based credential ordering
- Login endpoint discovery
- Fingerprint-based matching
"""

from .schema import (
    Credential,
    CredentialProfile,
    MatchRule,
    LoginEndpoint,
    CredentialSource,
)
from .loader import (
    load_builtin_credentials,
    load_all_credentials,
    get_credentials_for_protocol,
    get_credentials_for_service,
    get_credential_stats,
)

__all__ = [
    # Schema
    "Credential",
    "CredentialProfile",
    "MatchRule",
    "LoginEndpoint",
    "CredentialSource",
    # Loader
    "load_builtin_credentials",
    "load_all_credentials",
    "get_credentials_for_protocol",
    "get_credentials_for_service",
    "get_credential_stats",
]
