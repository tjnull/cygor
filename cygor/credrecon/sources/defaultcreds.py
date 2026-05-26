"""
DefaultCreds-cheat-sheet Source
================================

Fetches default credentials from the DefaultCreds-cheat-sheet GitHub repository.
https://github.com/ihebski/DefaultCreds-cheat-sheet

The repository provides a CSV file with vendor, product, and default credentials.
"""

import csv
import io
import logging
import requests
from datetime import datetime
from typing import List, Any, Optional

from .base import CredentialSource, SourceConfig, FetchResult
from .cache import CredentialCache
from ..credentials.schema import Credential, CredentialSource as CredSource

logger = logging.getLogger("credrecon.sources.defaultcreds")


class DefaultCredsSource(CredentialSource):
    """
    Fetches credentials from DefaultCreds-cheat-sheet.

    The source provides a CSV file with columns:
    - Product/Vendor
    - Username
    - Password
    """

    # URL to the raw CSV file
    CSV_URL = "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv"

    # Alternative URLs if main fails
    BACKUP_URLS = [
        "https://cdn.jsdelivr.net/gh/ihebski/DefaultCreds-cheat-sheet@main/DefaultCreds-Cheat-Sheet.csv",
    ]

    def __init__(self, config: SourceConfig = None, cache: CredentialCache = None):
        """
        Initialize the source.

        Args:
            config: Source configuration
            cache: Credential cache instance
        """
        super().__init__(config)
        self.cache = cache or CredentialCache()

    def _default_config(self) -> SourceConfig:
        """Return default configuration."""
        return SourceConfig(
            name="defaultcreds",
            enabled=True,
            cache_ttl_hours=24,
            timeout_seconds=30,
            max_retries=3,
        )

    @property
    def source_name(self) -> str:
        return "defaultcreds"

    @property
    def source_url(self) -> str:
        return self.CSV_URL

    def fetch(self, force: bool = False) -> FetchResult:
        """
        Fetch credentials from the DefaultCreds repository.

        Args:
            force: Force fetch even if cache is valid

        Returns:
            FetchResult with credentials or error
        """
        # Check cache first
        if not force:
            cached = self.cache.get(self.source_name)
            if cached:
                logger.info(f"Using cached credentials from {self.source_name}")
                credentials = []
                for cred_data in cached.credentials:
                    try:
                        credentials.append(Credential.from_dict(cred_data))
                    except Exception:
                        pass

                return FetchResult(
                    success=True,
                    credentials=credentials,
                    source_name=self.source_name,
                    metadata={"from_cache": True},
                )

        # Fetch from remote
        urls = [self.CSV_URL] + self.BACKUP_URLS
        raw_data = None
        last_error = None

        for url in urls:
            try:
                logger.info(f"Fetching credentials from {url}")
                response = requests.get(
                    url,
                    timeout=self.config.timeout_seconds,
                    headers={"User-Agent": self.config.user_agent},
                )
                response.raise_for_status()
                raw_data = response.text
                break

            except requests.RequestException as e:
                last_error = str(e)
                logger.warning(f"Failed to fetch from {url}: {e}")
                continue

        if raw_data is None:
            return FetchResult(
                success=False,
                source_name=self.source_name,
                error_message=f"Failed to fetch from all URLs: {last_error}",
            )

        # Parse the CSV data
        try:
            credentials = self.parse(raw_data)

            # Cache the results
            self.cache.put(
                source_name=self.source_name,
                credentials=credentials,
                ttl_hours=self.config.cache_ttl_hours,
                metadata={
                    "url": self.CSV_URL,
                    "raw_count": len(raw_data.split('\n')),
                },
            )

            return FetchResult(
                success=True,
                credentials=credentials,
                source_name=self.source_name,
                raw_count=len(raw_data.split('\n')),
                metadata={"from_cache": False},
            )

        except Exception as e:
            logger.error(f"Failed to parse DefaultCreds data: {e}")
            return FetchResult(
                success=False,
                source_name=self.source_name,
                error_message=f"Parse error: {str(e)}",
            )

    def parse(self, raw_data: str) -> List[Credential]:
        """
        Parse CSV data into Credential objects.

        CSV format:
        Product/Vendor,Username,Password

        Args:
            raw_data: Raw CSV content

        Returns:
            List of parsed Credential objects
        """
        credentials = []
        seen = set()  # Track duplicates

        # Parse CSV
        reader = csv.reader(io.StringIO(raw_data))

        # Skip header row
        try:
            header = next(reader)
            logger.debug(f"CSV header: {header}")
        except StopIteration:
            return credentials

        for row in reader:
            if len(row) < 3:
                continue

            # Extract fields
            product_vendor = row[0].strip()
            username = row[1].strip() if len(row) > 1 else ""
            password = row[2].strip() if len(row) > 2 else ""

            # Skip empty rows
            if not product_vendor or (not username and not password):
                continue

            # Parse vendor and product from combined field
            vendor, product = self._parse_vendor_product(product_vendor)

            # Deduplicate
            key = (username, password, vendor or "", product or "")
            if key in seen:
                continue
            seen.add(key)

            # Determine category and protocols
            category = self.determine_category(vendor, product)
            protocols = self.determine_protocols(product)

            # Create credential
            cred = Credential(
                username=username,
                password=password,
                priority=40,  # Lower priority than builtin
                source=CredSource.EXTERNAL,
                vendor=vendor,
                product=product,
                category=category,
                protocols=protocols,
                description=f"From DefaultCreds-cheat-sheet: {product_vendor}",
                tags=["defaultcreds", "external"],
            )
            credentials.append(cred)

        logger.info(f"Parsed {len(credentials)} credentials from DefaultCreds")
        return credentials

    def _parse_vendor_product(self, combined: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse vendor and product from combined string.

        Examples:
        - "Cisco IOS" -> ("Cisco", "IOS")
        - "Apache Tomcat" -> ("Apache", "Tomcat")
        - "MySQL" -> (None, "MySQL")

        Args:
            combined: Combined vendor/product string

        Returns:
            Tuple of (vendor, product)
        """
        if not combined:
            return None, None

        # Known vendor prefixes
        vendors = {
            "cisco": "Cisco",
            "juniper": "Juniper",
            "fortinet": "Fortinet",
            "palo alto": "Palo Alto",
            "f5": "F5",
            "hp": "HP",
            "dell": "Dell",
            "ibm": "IBM",
            "oracle": "Oracle",
            "microsoft": "Microsoft",
            "apache": "Apache",
            "vmware": "VMware",
            "citrix": "Citrix",
            "synology": "Synology",
            "qnap": "QNAP",
            "hikvision": "Hikvision",
            "dahua": "Dahua",
            "axis": "Axis",
            "ubiquiti": "Ubiquiti",
            "netgear": "NETGEAR",
            "tp-link": "TP-Link",
            "d-link": "D-Link",
            "zyxel": "ZyXEL",
            "aruba": "Aruba",
            "brocade": "Brocade",
            "mikrotik": "MikroTik",
            "ruckus": "Ruckus",
            "samsung": "Samsung",
            "lg": "LG",
            "brother": "Brother",
            "epson": "Epson",
            "canon": "Canon",
            "xerox": "Xerox",
            "ricoh": "Ricoh",
            "lexmark": "Lexmark",
            "siemens": "Siemens",
            "schneider": "Schneider",
            "abb": "ABB",
            "rockwell": "Rockwell",
            "honeywell": "Honeywell",
        }

        combined_lower = combined.lower()

        # Try to extract vendor
        for prefix, vendor in vendors.items():
            if combined_lower.startswith(prefix):
                product = combined[len(prefix):].strip()
                if product.startswith("-") or product.startswith("_"):
                    product = product[1:].strip()
                return vendor, product if product else combined

        # No known vendor found - use whole string as product
        # Try to split on common delimiters
        for delimiter in [" - ", "/", " "]:
            if delimiter in combined:
                parts = combined.split(delimiter, 1)
                if len(parts) == 2 and len(parts[0]) > 2:
                    return parts[0].strip(), parts[1].strip()

        return None, combined


def create_defaultcreds_source(config: SourceConfig = None) -> DefaultCredsSource:
    """Factory function to create DefaultCreds source."""
    return DefaultCredsSource(config=config)
