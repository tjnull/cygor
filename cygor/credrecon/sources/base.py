"""
Base classes for external credential sources.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from ..credentials.schema import Credential, CredentialCategory, CredentialSource as CredSource

logger = logging.getLogger("credrecon.sources")


@dataclass
class SourceConfig:
    """Configuration for a credential source."""
    name: str
    enabled: bool = True
    cache_ttl_hours: int = 24  # How long to cache results
    timeout_seconds: int = 30  # Request timeout
    max_retries: int = 3
    user_agent: str = "Cygor/1.0"


@dataclass
class FetchResult:
    """Result of fetching credentials from a source."""
    success: bool
    credentials: List[Credential] = field(default_factory=list)
    source_name: str = ""
    fetch_time: Optional[datetime] = None
    error_message: Optional[str] = None
    raw_count: int = 0  # Count before deduplication/filtering
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.fetch_time is None:
            self.fetch_time = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "source_name": self.source_name,
            "fetch_time": self.fetch_time.isoformat() if self.fetch_time else None,
            "credential_count": len(self.credentials),
            "raw_count": self.raw_count,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class CredentialSource(ABC):
    """
    Abstract base class for external credential sources.

    Each source implementation must provide:
    - fetch(): Download credentials from the source
    - parse(): Parse raw data into Credential objects
    - get_cache_key(): Unique key for caching
    """

    def __init__(self, config: SourceConfig = None):
        """
        Initialize the source.

        Args:
            config: Source configuration (uses defaults if not provided)
        """
        self.config = config or self._default_config()
        self._last_fetch: Optional[datetime] = None
        self._cached_result: Optional[FetchResult] = None

    @abstractmethod
    def _default_config(self) -> SourceConfig:
        """Return default configuration for this source."""
        pass

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Return the source name identifier."""
        pass

    @property
    @abstractmethod
    def source_url(self) -> str:
        """Return the primary URL for this source."""
        pass

    @property
    def cache_ttl(self) -> timedelta:
        """Return cache time-to-live as timedelta."""
        return timedelta(hours=self.config.cache_ttl_hours)

    def is_cache_valid(self) -> bool:
        """Check if cached results are still valid."""
        if self._last_fetch is None or self._cached_result is None:
            return False
        age = datetime.now() - self._last_fetch
        return age < self.cache_ttl

    @abstractmethod
    def fetch(self, force: bool = False) -> FetchResult:
        """
        Fetch credentials from the source.

        Args:
            force: Force fetch even if cache is valid

        Returns:
            FetchResult with credentials or error
        """
        pass

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Credential]:
        """
        Parse raw data into Credential objects.

        Args:
            raw_data: Raw data from the source (format varies by source)

        Returns:
            List of parsed Credential objects
        """
        pass

    def get_cache_key(self) -> str:
        """Return unique cache key for this source."""
        return f"credrecon_source_{self.source_name}"

    def normalize_vendor(self, vendor: str) -> Optional[str]:
        """Normalize vendor name for consistency."""
        if not vendor:
            return None
        vendor = vendor.strip()
        if not vendor or vendor.lower() in ["unknown", "n/a", "-", ""]:
            return None
        return vendor

    def normalize_product(self, product: str) -> Optional[str]:
        """Normalize product name for consistency."""
        if not product:
            return None
        product = product.strip()
        if not product or product.lower() in ["unknown", "n/a", "-", ""]:
            return None
        return product

    def determine_category(
        self,
        vendor: str = None,
        product: str = None,
        protocol: str = None,
    ) -> CredentialCategory:
        """
        Determine credential category from context.

        Args:
            vendor: Vendor name
            product: Product name
            protocol: Protocol type

        Returns:
            Best-guess CredentialCategory
        """
        # Check for enterprise indicators
        enterprise_keywords = [
            "cisco", "juniper", "fortinet", "paloalto", "f5", "aruba",
            "hp", "dell", "brocade", "checkpoint", "sonicwall"
        ]

        # Check for IoT indicators
        iot_keywords = [
            "camera", "dvr", "nvr", "printer", "nas", "router",
            "hikvision", "dahua", "axis", "synology", "qnap", "ups"
        ]

        # Check for cloud/devops indicators
        cloud_keywords = [
            "jenkins", "gitlab", "grafana", "docker", "kubernetes",
            "prometheus", "kibana", "harbor", "nexus"
        ]

        # Check for database indicators
        db_keywords = [
            "mysql", "postgres", "oracle", "mssql", "mongodb",
            "redis", "cassandra", "couchdb", "elasticsearch"
        ]

        # Check for web indicators
        web_keywords = [
            "wordpress", "drupal", "joomla", "tomcat", "weblogic",
            "jboss", "apache", "nginx", "phpmyadmin"
        ]

        # Combine all searchable text
        search_text = " ".join([
            vendor or "",
            product or "",
            protocol or ""
        ]).lower()

        if any(kw in search_text for kw in enterprise_keywords):
            return CredentialCategory.ENTERPRISE
        elif any(kw in search_text for kw in iot_keywords):
            return CredentialCategory.IOT
        elif any(kw in search_text for kw in cloud_keywords):
            return CredentialCategory.CLOUD
        elif any(kw in search_text for kw in db_keywords):
            return CredentialCategory.DATABASE
        elif any(kw in search_text for kw in web_keywords):
            return CredentialCategory.WEB

        return CredentialCategory.GENERIC

    def determine_protocols(
        self,
        product: str = None,
        port: int = None,
    ) -> List[str]:
        """
        Determine applicable protocols from context.

        Args:
            product: Product name
            port: Port number hint

        Returns:
            List of protocol names
        """
        protocols = []

        # Check product name for protocol hints
        if product:
            product_lower = product.lower()
            if "ssh" in product_lower:
                protocols.append("ssh")
            if "telnet" in product_lower:
                protocols.append("telnet")
            if "ftp" in product_lower:
                protocols.append("ftp")
            if "web" in product_lower or "http" in product_lower:
                protocols.extend(["http", "https"])
            if "mysql" in product_lower:
                protocols.append("mysql")
            if "postgres" in product_lower:
                protocols.append("postgres")
            if "mongodb" in product_lower:
                protocols.append("mongodb")
            if "redis" in product_lower:
                protocols.append("redis")
            if "snmp" in product_lower:
                protocols.append("snmp")
            if "vnc" in product_lower:
                protocols.append("vnc")
            if "rdp" in product_lower:
                protocols.append("rdp")

        # Check port for protocol hints
        port_map = {
            22: "ssh",
            23: "telnet",
            21: "ftp",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgres",
            1433: "mssql",
            27017: "mongodb",
            6379: "redis",
            161: "snmp",
            5900: "vnc",
            3389: "rdp",
        }

        if port and port in port_map:
            proto = port_map[port]
            if proto not in protocols:
                protocols.append(proto)

        # Default to HTTP if nothing specific
        if not protocols:
            protocols = ["http", "https", "ssh", "telnet"]

        return protocols
