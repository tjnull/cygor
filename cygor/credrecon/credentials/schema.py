"""
Credential Schema Definitions
=============================

Defines the data structures for the hierarchical credential database.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class CredentialSource(Enum):
    """Source of credential data."""
    BUILTIN = "builtin"           # Shipped with cygor
    EXTERNAL = "external"         # Generic external source
    DEFAULTCREDS = "defaultcreds" # DefaultCreds-cheat-sheet
    CIRT = "cirt"                 # CIRT.net default passwords
    CUSTOM = "custom"             # User-provided credentials


class CredentialCategory(Enum):
    """Category of target device/service."""
    GENERIC = "generic"           # Protocol-level defaults
    ENTERPRISE = "enterprise"     # Enterprise network devices
    IOT = "iot"                   # IoT and embedded devices
    CLOUD = "cloud"               # Cloud and DevOps tools
    DATABASE = "database"         # Database systems
    WEB = "web"                   # Web applications


class AuthType(Enum):
    """Authentication mechanism type."""
    BASIC = "basic"               # HTTP Basic Auth
    DIGEST = "digest"             # HTTP Digest Auth
    FORM = "form"                 # HTML form-based login
    NTLM = "ntlm"                 # NTLM authentication
    BEARER = "bearer"             # Bearer token
    API_KEY = "api_key"           # API key authentication
    SSH = "ssh"                   # SSH password auth
    DATABASE = "database"         # Direct database connection
    PROTOCOL = "protocol"         # Protocol-native auth (SNMP, VNC, etc.)


@dataclass
class LoginEndpoint:
    """
    Defines a known login endpoint for a service.

    Used to find the correct URL/path for authentication testing.
    """
    path: str                                    # URL path (e.g., "/login", "/wp-admin/")
    method: str = "POST"                         # HTTP method (GET, POST)
    auth_type: AuthType = AuthType.FORM          # Type of authentication
    username_field: str = "username"             # Form field for username
    password_field: str = "password"             # Form field for password
    submit_field: Optional[str] = None           # Submit button field name
    extra_fields: Dict[str, str] = field(default_factory=dict)  # CSRF tokens, etc.
    success_indicators: List[str] = field(default_factory=list)  # Strings indicating success
    failure_indicators: List[str] = field(default_factory=list)  # Strings indicating failure
    requires_csrf: bool = False                  # Whether CSRF token is needed
    csrf_field: Optional[str] = None             # CSRF token field name
    redirect_on_success: Optional[str] = None    # Expected redirect path on success


@dataclass
class MatchRule:
    """
    Rule for matching a credential to a service fingerprint.

    Used by the credential selector to score credential relevance.
    """
    field: str                    # Fingerprint field to match (vendor, product, version, etc.)
    pattern: str                  # Regex pattern or exact match
    is_regex: bool = False        # Whether pattern is regex
    weight: float = 1.0           # Weight contribution to match score (0.0-1.0)
    required: bool = False        # If True, credential is excluded if rule doesn't match


@dataclass
class Credential:
    """
    A single credential entry.

    Contains username/password and metadata for matching and prioritization.
    """
    username: str
    password: str

    # Priority and source
    priority: int = 50                           # 1-100, higher = try first
    source: CredentialSource = CredentialSource.BUILTIN

    # Targeting metadata
    vendor: Optional[str] = None                 # Vendor name (cisco, juniper, etc.)
    product: Optional[str] = None                # Product name (ios, junos, grafana)
    model: Optional[str] = None                  # Specific model
    firmware_versions: List[str] = field(default_factory=list)  # Version patterns

    # Classification
    category: CredentialCategory = CredentialCategory.GENERIC
    protocols: List[str] = field(default_factory=list)  # Applicable protocols
    tags: List[str] = field(default_factory=list)       # Additional tags

    # Documentation
    description: Optional[str] = None
    reference_url: Optional[str] = None          # Source documentation

    # Match rules for fingerprint-based selection
    match_rules: List[MatchRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "username": self.username,
            "password": self.password,
            "priority": self.priority,
            "source": self.source.value,
            "vendor": self.vendor,
            "product": self.product,
            "model": self.model,
            "firmware_versions": self.firmware_versions,
            "category": self.category.value,
            "protocols": self.protocols,
            "tags": self.tags,
            "description": self.description,
            "reference_url": self.reference_url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: CredentialSource = CredentialSource.BUILTIN) -> "Credential":
        """Create from dictionary."""
        # Handle source enum
        if isinstance(data.get("source"), str):
            try:
                source = CredentialSource(data["source"])
            except ValueError:
                pass

        # Handle category enum
        category = CredentialCategory.GENERIC
        if isinstance(data.get("category"), str):
            try:
                category = CredentialCategory(data["category"])
            except ValueError:
                pass

        # Parse match rules if present
        match_rules = []
        for rule_data in data.get("match_rules", []):
            match_rules.append(MatchRule(
                field=rule_data.get("field", "product"),
                pattern=rule_data.get("pattern", ""),
                is_regex=rule_data.get("is_regex", False),
                weight=rule_data.get("weight", 1.0),
                required=rule_data.get("required", False),
            ))

        return cls(
            username=data.get("username", ""),
            password=data.get("password", ""),
            priority=data.get("priority", 50),
            source=source,
            vendor=data.get("vendor"),
            product=data.get("product"),
            model=data.get("model"),
            firmware_versions=data.get("firmware_versions", []),
            category=category,
            protocols=data.get("protocols", []),
            tags=data.get("tags", []),
            description=data.get("description"),
            reference_url=data.get("reference_url"),
            match_rules=match_rules,
        )


@dataclass
class CredentialProfile:
    """
    A service-specific credential profile.

    Groups credentials with login endpoint information for a specific service.
    """
    name: str                                    # Profile name (e.g., "jenkins", "grafana")
    vendor: str                                  # Vendor name
    product: str                                 # Product name

    # Applicable protocols
    protocols: List[str] = field(default_factory=list)  # ssh, http, telnet, etc.

    # Login endpoints for HTTP-based services
    login_endpoints: List[LoginEndpoint] = field(default_factory=list)

    # Associated credentials
    credentials: List[Credential] = field(default_factory=list)

    # Fingerprint matching patterns
    fingerprint_patterns: List[str] = field(default_factory=list)  # Patterns to match in fingerprint

    # Detection hints
    port_hints: List[int] = field(default_factory=list)            # Common ports
    banner_patterns: List[str] = field(default_factory=list)       # Banner regex patterns
    http_indicators: List[str] = field(default_factory=list)       # HTTP content indicators

    # Category
    category: CredentialCategory = CredentialCategory.GENERIC

    # Documentation
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "vendor": self.vendor,
            "product": self.product,
            "protocols": self.protocols,
            "login_endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "auth_type": ep.auth_type.value,
                    "username_field": ep.username_field,
                    "password_field": ep.password_field,
                }
                for ep in self.login_endpoints
            ],
            "credentials": [c.to_dict() for c in self.credentials],
            "fingerprint_patterns": self.fingerprint_patterns,
            "port_hints": self.port_hints,
            "banner_patterns": self.banner_patterns,
            "http_indicators": self.http_indicators,
            "category": self.category.value,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CredentialProfile":
        """Create from dictionary."""
        # Parse login endpoints
        login_endpoints = []
        for ep_data in data.get("login_endpoints", []):
            auth_type = AuthType.FORM
            if isinstance(ep_data.get("auth_type"), str):
                try:
                    auth_type = AuthType(ep_data["auth_type"])
                except ValueError:
                    pass

            login_endpoints.append(LoginEndpoint(
                path=ep_data.get("path", "/"),
                method=ep_data.get("method", "POST"),
                auth_type=auth_type,
                username_field=ep_data.get("username_field", "username"),
                password_field=ep_data.get("password_field", "password"),
                submit_field=ep_data.get("submit_field"),
                extra_fields=ep_data.get("extra_fields", {}),
                success_indicators=ep_data.get("success_indicators", []),
                failure_indicators=ep_data.get("failure_indicators", []),
                requires_csrf=ep_data.get("requires_csrf", False),
                csrf_field=ep_data.get("csrf_field"),
                redirect_on_success=ep_data.get("redirect_on_success"),
            ))

        # Parse credentials
        credentials = [Credential.from_dict(c) for c in data.get("credentials", [])]

        # Parse category
        category = CredentialCategory.GENERIC
        if isinstance(data.get("category"), str):
            try:
                category = CredentialCategory(data["category"])
            except ValueError:
                pass

        return cls(
            name=data.get("name", ""),
            vendor=data.get("vendor", ""),
            product=data.get("product", ""),
            protocols=data.get("protocols", []),
            login_endpoints=login_endpoints,
            credentials=credentials,
            fingerprint_patterns=data.get("fingerprint_patterns", []),
            port_hints=data.get("port_hints", []),
            banner_patterns=data.get("banner_patterns", []),
            http_indicators=data.get("http_indicators", []),
            category=category,
            description=data.get("description"),
        )


@dataclass
class CredentialDatabase:
    """
    The complete credential database.

    Contains all credentials organized by protocol and service profiles.
    """
    # Protocol-indexed credentials (for quick lookup)
    by_protocol: Dict[str, List[Credential]] = field(default_factory=dict)

    # Service profiles (for fingerprint-based matching)
    profiles: Dict[str, CredentialProfile] = field(default_factory=dict)

    # All credentials (for full-database operations)
    all_credentials: List[Credential] = field(default_factory=list)

    # Metadata
    version: str = "1.0"
    last_updated: Optional[str] = None
    sources: List[str] = field(default_factory=list)

    def add_credential(self, cred: Credential) -> None:
        """Add a credential to the database."""
        self.all_credentials.append(cred)

        # Index by protocol
        for protocol in cred.protocols:
            if protocol not in self.by_protocol:
                self.by_protocol[protocol] = []
            self.by_protocol[protocol].append(cred)

    def add_profile(self, profile: CredentialProfile) -> None:
        """Add a service profile to the database."""
        self.profiles[profile.name] = profile

        # Also add credentials from profile
        for cred in profile.credentials:
            # Set vendor/product from profile if not set
            if not cred.vendor:
                cred.vendor = profile.vendor
            if not cred.product:
                cred.product = profile.product
            self.add_credential(cred)

    def get_credentials_for_protocol(self, protocol: str) -> List[Credential]:
        """Get all credentials for a protocol, sorted by priority."""
        creds = self.by_protocol.get(protocol, [])
        return sorted(creds, key=lambda c: c.priority, reverse=True)

    def get_profile(self, name: str) -> Optional[CredentialProfile]:
        """Get a service profile by name."""
        return self.profiles.get(name)

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        by_category = {}
        by_source = {}
        by_protocol = {}
        by_vendor = {}

        for cred in self.all_credentials:
            # Count by category
            cat = cred.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

            # Count by source
            src = cred.source.value
            by_source[src] = by_source.get(src, 0) + 1

            # Count by protocol
            for proto in cred.protocols:
                by_protocol[proto] = by_protocol.get(proto, 0) + 1

            # Count by vendor
            vendor = cred.vendor or "Unknown"
            by_vendor[vendor] = by_vendor.get(vendor, 0) + 1

        return {
            "total_credentials": len(self.all_credentials),
            "total_profiles": len(self.profiles),
            "by_category": by_category,
            "by_source": by_source,
            "by_protocol": by_protocol,
            "by_vendor": by_vendor,
            "version": self.version,
            "last_updated": self.last_updated,
            "sources": self.sources,
        }
