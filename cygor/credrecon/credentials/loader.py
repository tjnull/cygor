"""
Credential Loader
=================

Loads and manages credentials from multiple sources:
- Builtin YAML files (shipped with cygor)
- External sources (DefaultCreds, CIRT.net)
- User-provided custom credentials
"""

import os
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from .schema import (
    Credential,
    CredentialProfile,
    CredentialDatabase,
    CredentialSource,
    CredentialCategory,
    LoginEndpoint,
    AuthType,
)

logger = logging.getLogger("credrecon.credentials")

# Directory containing builtin credential files
BUILTIN_DIR = Path(__file__).parent / "builtin"

# Cache for loaded credentials
_credential_cache: Optional[CredentialDatabase] = None
_cache_timestamp: Optional[datetime] = None


def load_yaml_file(filepath: Path) -> Dict[str, Any]:
    """Load a YAML file and return its contents."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"Failed to load YAML file {filepath}: {e}")
        return {}


def parse_legacy_credential(data: Dict[str, Any], protocol: str) -> Credential:
    """
    Parse a credential from legacy format (default_credentials.yaml).

    Legacy format:
    - username: "admin"
      password: "admin"
      service: "generic"
      description: "Common default"
    """
    # Determine category from service field
    service = data.get("service", "generic")
    category = CredentialCategory.GENERIC

    # Map common service types to categories
    enterprise_services = ["cisco", "juniper", "fortinet", "paloalto", "f5", "aruba"]
    iot_services = ["axis-camera", "hikvision", "dahua", "synology", "qnap", "hp-printer", "router"]
    cloud_services = ["docker", "kubernetes", "jenkins", "gitlab", "grafana", "portainer", "nexus"]
    database_services = ["mysql", "postgres", "mssql", "mongodb", "redis", "oracle", "cassandra"]
    web_services = ["tomcat", "wordpress", "drupal", "joomla", "webmin", "phpmyadmin"]

    service_lower = service.lower()
    if any(s in service_lower for s in enterprise_services):
        category = CredentialCategory.ENTERPRISE
    elif any(s in service_lower for s in iot_services):
        category = CredentialCategory.IOT
    elif any(s in service_lower for s in cloud_services):
        category = CredentialCategory.CLOUD
    elif any(s in service_lower for s in database_services):
        category = CredentialCategory.DATABASE
    elif any(s in service_lower for s in web_services):
        category = CredentialCategory.WEB

    return Credential(
        username=data.get("username", ""),
        password=data.get("password", ""),
        priority=data.get("priority", 50),
        source=CredentialSource.BUILTIN,
        vendor=data.get("vendor"),
        product=data.get("service") if data.get("service") != "generic" else None,
        category=category,
        protocols=[protocol],
        description=data.get("description"),
    )


def parse_new_credential(data: Dict[str, Any], defaults: Dict[str, Any] = None) -> Credential:
    """
    Parse a credential from new hierarchical format.

    New format:
    - username: "admin"
      password: "admin"
      priority: 90
      vendor: "cisco"
      product: "ios"
      protocols: ["ssh", "telnet", "http"]
      category: "enterprise"
      tags: ["network-device", "router"]
    """
    defaults = defaults or {}

    # Merge with defaults
    merged = {**defaults, **data}

    return Credential.from_dict(merged)


def parse_profile(data: Dict[str, Any]) -> CredentialProfile:
    """Parse a credential profile from YAML data."""
    return CredentialProfile.from_dict(data)


def load_builtin_credentials() -> CredentialDatabase:
    """
    Load all builtin credential files.

    Returns a CredentialDatabase populated with credentials from all
    builtin YAML files in the builtin/ directory.
    """
    db = CredentialDatabase(
        version="1.0",
        last_updated=datetime.now().isoformat(),
        sources=["builtin"],
    )

    if not BUILTIN_DIR.exists():
        logger.warning(f"Builtin credentials directory not found: {BUILTIN_DIR}")
        return db

    # Load all YAML files in builtin directory
    for yaml_file in BUILTIN_DIR.glob("*.yaml"):
        logger.debug(f"Loading credentials from {yaml_file.name}")
        data = load_yaml_file(yaml_file)

        if not data:
            continue

        # Determine format based on content
        if "profiles" in data:
            # New format with profiles
            for profile_data in data.get("profiles", []):
                profile = parse_profile(profile_data)
                db.add_profile(profile)

        elif "credentials" in data:
            # New format with credentials list (hierarchical per vendor/product)
            defaults = data.get("defaults", {})
            for entry in data.get("credentials", []):
                # Each entry can have multiple nested credentials
                if "credentials" in entry:
                    # Hierarchical format: entry has vendor/product/protocols with nested credentials
                    entry_defaults = {
                        "vendor": entry.get("vendor"),
                        "product": entry.get("product"),
                        "category": entry.get("category"),
                        "protocols": entry.get("protocols", []),
                        "login_paths": entry.get("login_paths", []),
                        "tags": entry.get("tags", []),
                    }
                    merged_defaults = {**defaults, **entry_defaults}

                    for cred_data in entry.get("credentials", []):
                        cred = parse_new_credential(cred_data, merged_defaults)
                        db.add_credential(cred)
                else:
                    # Flat format: entry is a single credential
                    cred = parse_new_credential(entry, defaults)
                    db.add_credential(cred)

        else:
            # Legacy format (protocol -> list of credentials)
            for protocol, creds_list in data.items():
                if not isinstance(creds_list, list):
                    continue

                for cred_data in creds_list:
                    if not isinstance(cred_data, dict):
                        continue

                    cred = parse_legacy_credential(cred_data, protocol)
                    db.add_credential(cred)

    logger.info(f"Loaded {len(db.all_credentials)} builtin credentials, {len(db.profiles)} profiles")
    return db


def load_legacy_credentials(filepath: Path) -> CredentialDatabase:
    """
    Load credentials from the legacy default_credentials.yaml format.

    This provides backward compatibility with the existing credential file.
    """
    db = CredentialDatabase(
        version="1.0",
        last_updated=datetime.now().isoformat(),
        sources=["legacy"],
    )

    data = load_yaml_file(filepath)
    if not data:
        return db

    for protocol, creds_list in data.items():
        if not isinstance(creds_list, list):
            continue

        for cred_data in creds_list:
            if not isinstance(cred_data, dict):
                continue

            cred = parse_legacy_credential(cred_data, protocol)
            db.add_credential(cred)

    return db


def load_all_credentials(
    include_builtin: bool = True,
    include_cached: bool = True,
    custom_files: List[Path] = None,
) -> CredentialDatabase:
    """
    Load credentials from all available sources.

    Args:
        include_builtin: Include builtin credentials
        include_cached: Include credentials from external source cache
        custom_files: Additional custom credential files to load

    Returns:
        Merged CredentialDatabase
    """
    global _credential_cache, _cache_timestamp

    # Use cache if available and recent (5 minutes)
    if _credential_cache is not None and _cache_timestamp is not None:
        age = (datetime.now() - _cache_timestamp).total_seconds()
        if age < 300:  # 5 minutes
            return _credential_cache

    db = CredentialDatabase(
        version="1.0",
        last_updated=datetime.now().isoformat(),
        sources=[],
    )

    # Load builtin credentials
    if include_builtin:
        builtin_db = load_builtin_credentials()
        merge_databases(db, builtin_db)
        db.sources.append("builtin")

    # Load cached external credentials
    if include_cached:
        cache_dir = Path.home() / ".cache" / "cygor" / "credentials"
        if cache_dir.exists():
            for cache_file in cache_dir.glob("*.yaml"):
                cached_db = load_yaml_file(cache_file)
                if cached_db:
                    # Parse cached credentials
                    for cred_data in cached_db.get("credentials", []):
                        cred = Credential.from_dict(cred_data)
                        db.add_credential(cred)
                    db.sources.append(cache_file.stem)

    # Load custom files
    if custom_files:
        for filepath in custom_files:
            if filepath.exists():
                custom_db = load_legacy_credentials(filepath)
                merge_databases(db, custom_db)
                db.sources.append(f"custom:{filepath.name}")

    # Update cache
    _credential_cache = db
    _cache_timestamp = datetime.now()

    return db


def merge_databases(target: CredentialDatabase, source: CredentialDatabase) -> None:
    """Merge source database into target, avoiding duplicates."""
    # Track existing credentials by (username, password, protocol) tuple
    existing = set()
    for cred in target.all_credentials:
        for proto in cred.protocols:
            existing.add((cred.username, cred.password, proto))

    # Add non-duplicate credentials
    for cred in source.all_credentials:
        for proto in cred.protocols:
            key = (cred.username, cred.password, proto)
            if key not in existing:
                target.add_credential(cred)
                existing.add(key)

    # Merge profiles (overwrite if exists)
    for name, profile in source.profiles.items():
        target.profiles[name] = profile


def get_credentials_for_protocol(
    protocol: str,
    db: CredentialDatabase = None,
    max_credentials: int = None,
) -> List[Credential]:
    """
    Get credentials for a specific protocol.

    Args:
        protocol: Protocol name (ssh, http, mysql, etc.)
        db: CredentialDatabase to use (loads all if not provided)
        max_credentials: Maximum number of credentials to return

    Returns:
        List of Credential objects, sorted by priority
    """
    if db is None:
        db = load_all_credentials()

    creds = db.get_credentials_for_protocol(protocol)

    if max_credentials:
        creds = creds[:max_credentials]

    return creds


def get_credentials_for_service(
    vendor: str = None,
    product: str = None,
    protocol: str = None,
    category: CredentialCategory = None,
    db: CredentialDatabase = None,
    max_credentials: int = None,
) -> Tuple[List[Credential], str]:
    """
    Get credentials matching specific service criteria.

    Uses fingerprint information to select the most relevant credentials.

    Args:
        vendor: Vendor name to match
        product: Product name to match
        protocol: Protocol to filter by
        category: Category to filter by
        db: CredentialDatabase to use
        max_credentials: Maximum credentials to return

    Returns:
        Tuple of (credentials, selection_rationale)
    """
    if db is None:
        db = load_all_credentials()

    candidates = []
    rationale_parts = []

    # Start with protocol-filtered credentials
    if protocol:
        candidates = list(db.get_credentials_for_protocol(protocol))
        rationale_parts.append(f"protocol={protocol}")
    else:
        candidates = list(db.all_credentials)

    # Filter by vendor
    if vendor:
        vendor_lower = vendor.lower()
        vendor_filtered = [c for c in candidates if c.vendor and vendor_lower in c.vendor.lower()]
        if vendor_filtered:
            candidates = vendor_filtered
            rationale_parts.append(f"vendor={vendor}")

    # Filter by product
    if product:
        product_lower = product.lower()
        product_filtered = [c for c in candidates if c.product and product_lower in c.product.lower()]
        if product_filtered:
            candidates = product_filtered
            rationale_parts.append(f"product={product}")

    # Filter by category
    if category:
        category_filtered = [c for c in candidates if c.category == category]
        if category_filtered:
            candidates = category_filtered
            rationale_parts.append(f"category={category.value}")

    # Sort by priority
    candidates.sort(key=lambda c: c.priority, reverse=True)

    # Limit results
    if max_credentials:
        candidates = candidates[:max_credentials]

    # Build rationale
    rationale = f"Selected {len(candidates)} credentials"
    if rationale_parts:
        rationale += f" matching: {', '.join(rationale_parts)}"

    return candidates, rationale


def get_profile_for_service(
    product: str = None,
    vendor: str = None,
    fingerprint_patterns: List[str] = None,
    db: CredentialDatabase = None,
) -> Optional[CredentialProfile]:
    """
    Find a credential profile matching service fingerprint.

    Args:
        product: Product name from fingerprint
        vendor: Vendor name from fingerprint
        fingerprint_patterns: Patterns to match in profile
        db: CredentialDatabase to use

    Returns:
        Matching CredentialProfile or None
    """
    if db is None:
        db = load_all_credentials()

    # Try exact product match first
    if product:
        product_lower = product.lower().replace(" ", "").replace("-", "")
        for name, profile in db.profiles.items():
            if product_lower in name.lower().replace("-", ""):
                return profile
            if product_lower in profile.product.lower().replace(" ", "").replace("-", ""):
                return profile

    # Try vendor match
    if vendor:
        vendor_lower = vendor.lower()
        matches = []
        for name, profile in db.profiles.items():
            if vendor_lower in profile.vendor.lower():
                matches.append(profile)
        if len(matches) == 1:
            return matches[0]

    # Try fingerprint pattern matching
    if fingerprint_patterns:
        for name, profile in db.profiles.items():
            for pattern in fingerprint_patterns:
                for fp_pattern in profile.fingerprint_patterns:
                    if pattern.lower() in fp_pattern.lower():
                        return profile

    return None


def get_credential_stats(db: CredentialDatabase = None) -> Dict[str, Any]:
    """
    Get statistics about the credential database.

    Args:
        db: CredentialDatabase to analyze

    Returns:
        Dictionary with credential statistics
    """
    if db is None:
        db = load_all_credentials()

    return db.get_stats()


def invalidate_cache() -> None:
    """Clear the credential cache to force reload."""
    global _credential_cache, _cache_timestamp
    _credential_cache = None
    _cache_timestamp = None


def get_credentials_by_fingerprint(
    protocol: str,
    fingerprint: Any = None,
    db: CredentialDatabase = None,
    max_credentials: int = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Get credentials prioritized by fingerprint match.

    This function is designed to be called from scanner.py with probe results.
    It returns credentials in legacy format (list of dicts) for compatibility.

    Priority order:
    1. Credentials matching product (if detected)
    2. Credentials matching vendor (if detected)
    3. Generic protocol credentials

    Args:
        protocol: Protocol name (ssh, http, mysql, etc.)
        fingerprint: ServiceFingerprint or dict with product/vendor info
        db: CredentialDatabase to use
        max_credentials: Maximum credentials to return

    Returns:
        Tuple of (credentials_list, selection_rationale)
        credentials_list is in legacy format: [{"username": ..., "password": ..., "service": ...}, ...]
    """
    if db is None:
        db = load_all_credentials()

    # Extract product/vendor from fingerprint
    product = None
    vendor = None

    if fingerprint:
        # Handle both dict and object formats
        if isinstance(fingerprint, dict):
            product = fingerprint.get("product")
            vendor = fingerprint.get("vendor")
        else:
            product = getattr(fingerprint, "product", None)
            vendor = getattr(fingerprint, "vendor", None)

    selected_creds = []
    rationale_parts = []
    seen_keys = set()

    def add_creds(creds: List[Credential], source: str) -> int:
        """Add credentials avoiding duplicates, return count added."""
        added = 0
        for cred in creds:
            key = (cred.username, cred.password)
            if key not in seen_keys:
                seen_keys.add(key)
                selected_creds.append(cred)
                added += 1
        if added > 0:
            rationale_parts.append(f"{added} {source}")
        return added

    # Priority 1: Product-specific credentials
    if product:
        product_creds = [c for c in db.all_credentials
                        if c.product and product.lower() in c.product.lower()
                        and (not c.protocols or protocol in c.protocols)]
        add_creds(product_creds, f"{product}-specific")

    # Priority 2: Vendor-specific credentials
    if vendor:
        vendor_creds = [c for c in db.all_credentials
                       if c.vendor and vendor.lower() in c.vendor.lower()
                       and (not c.protocols or protocol in c.protocols)
                       and (c.username, c.password) not in seen_keys]
        add_creds(vendor_creds, f"{vendor}-vendor")

    # Priority 3: Generic protocol credentials
    protocol_creds = db.get_credentials_for_protocol(protocol)
    generic_creds = [c for c in protocol_creds if (c.username, c.password) not in seen_keys]
    add_creds(generic_creds, "generic")

    # Sort by priority
    selected_creds.sort(key=lambda c: c.priority, reverse=True)

    # Limit results
    if max_credentials and len(selected_creds) > max_credentials:
        selected_creds = selected_creds[:max_credentials]

    # Convert to legacy format
    legacy_format = []
    for cred in selected_creds:
        legacy_format.append({
            "username": cred.username,
            "password": cred.password,
            "service": cred.product or "generic",
            "description": cred.description,
            "vendor": cred.vendor,
            "product": cred.product,
        })

    # Build rationale
    if product or vendor:
        service_name = product or vendor or "unknown"
        rationale = f"Selected {len(legacy_format)} credentials for {service_name}: {', '.join(rationale_parts)}"
    else:
        rationale = f"Selected {len(legacy_format)} generic {protocol} credentials"

    return legacy_format, rationale


# Legacy compatibility function
def load_default_credentials_legacy() -> Dict[str, List[Dict[str, Any]]]:
    """
    Load credentials in legacy format for backward compatibility.

    Returns a dictionary matching the old DEFAULT_CREDENTIALS_DB format:
    {
        "http": [{"username": "admin", "password": "admin", "service": "generic"}, ...],
        "ssh": [...],
        ...
    }
    """
    # First try to load the new format
    db = load_all_credentials()

    # If no credentials loaded, fall back to legacy file
    if not db.all_credentials:
        legacy_file = Path(__file__).parent.parent / "default_credentials.yaml"
        if legacy_file.exists():
            return load_yaml_file(legacy_file)
        return {}

    # Convert new format to legacy format
    result = {}
    for cred in db.all_credentials:
        for protocol in cred.protocols:
            if protocol not in result:
                result[protocol] = []
            result[protocol].append({
                "username": cred.username,
                "password": cred.password,
                "service": cred.product or "generic",
                "description": cred.description,
            })

    return result
