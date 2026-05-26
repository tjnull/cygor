"""
CIRT.net Default Passwords Source
=================================

Fetches default passwords from CIRT.net.
https://cirt.net/passwords

CIRT.net provides a comprehensive database of default passwords
organized by vendor and product.
"""

import re
import logging
import requests
from typing import List, Any, Optional
from datetime import datetime

# Optional dependency - graceful handling if not installed
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BeautifulSoup = None
    BS4_AVAILABLE = False

from .base import CredentialSource, SourceConfig, FetchResult
from .cache import CredentialCache
from ..credentials.schema import Credential, CredentialSource as CredSource

logger = logging.getLogger("credrecon.sources.cirt")


class CIRTSource(CredentialSource):
    """
    Fetches credentials from CIRT.net default passwords database.

    The source requires scraping the web interface since no API is available.
    """

    # Base URL for CIRT.net passwords
    BASE_URL = "https://cirt.net/passwords"

    # Vendor list URL
    VENDOR_LIST_URL = "https://cirt.net/passwords"

    def __init__(self, config: SourceConfig = None, cache: CredentialCache = None):
        """
        Initialize the source.

        Args:
            config: Source configuration
            cache: Credential cache instance
        """
        super().__init__(config)
        self.cache = cache or CredentialCache()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
        })

    def _default_config(self) -> SourceConfig:
        """Return default configuration."""
        return SourceConfig(
            name="cirt",
            enabled=True,
            cache_ttl_hours=48,  # CIRT data changes less frequently
            timeout_seconds=30,
            max_retries=3,
        )

    @property
    def source_name(self) -> str:
        return "cirt"

    @property
    def source_url(self) -> str:
        return self.BASE_URL

    def fetch(self, force: bool = False) -> FetchResult:
        """
        Fetch credentials from CIRT.net.

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

        # Check if BeautifulSoup is available
        if not BS4_AVAILABLE:
            logger.warning("beautifulsoup4 not installed - CIRT.net source unavailable")
            return FetchResult(
                success=False,
                source_name=self.source_name,
                error_message="beautifulsoup4 package not installed. Run: pip install beautifulsoup4",
            )

        try:
            # Fetch the vendor list page
            logger.info(f"Fetching vendor list from {self.VENDOR_LIST_URL}")
            response = self.session.get(
                self.VENDOR_LIST_URL,
                timeout=self.config.timeout_seconds,
            )
            response.raise_for_status()

            # Parse vendors and get their password pages
            vendors = self._parse_vendor_list(response.text)
            logger.info(f"Found {len(vendors)} vendors on CIRT.net")

            # Fetch credentials for each vendor (limit to avoid too many requests)
            all_credentials = []
            max_vendors = 100  # Limit to prevent excessive requests

            for i, (vendor_name, vendor_url) in enumerate(vendors[:max_vendors]):
                try:
                    vendor_creds = self._fetch_vendor_credentials(vendor_name, vendor_url)
                    all_credentials.extend(vendor_creds)

                    if i % 10 == 0:
                        logger.debug(f"Progress: {i}/{min(len(vendors), max_vendors)} vendors")

                except Exception as e:
                    logger.debug(f"Failed to fetch credentials for {vendor_name}: {e}")
                    continue

            # Cache the results
            self.cache.put(
                source_name=self.source_name,
                credentials=all_credentials,
                ttl_hours=self.config.cache_ttl_hours,
                metadata={
                    "url": self.BASE_URL,
                    "vendors_count": len(vendors),
                },
            )

            return FetchResult(
                success=True,
                credentials=all_credentials,
                source_name=self.source_name,
                raw_count=len(vendors),
                metadata={"from_cache": False, "vendors_fetched": min(len(vendors), max_vendors)},
            )

        except Exception as e:
            logger.error(f"Failed to fetch from CIRT.net: {e}")
            return FetchResult(
                success=False,
                source_name=self.source_name,
                error_message=str(e),
            )

    def _parse_vendor_list(self, html: str) -> List[tuple[str, str]]:
        """
        Parse the vendor list page.

        Args:
            html: HTML content of the vendor list page

        Returns:
            List of (vendor_name, vendor_url) tuples
        """
        vendors = []
        soup = BeautifulSoup(html, 'html.parser')

        # CIRT.net uses a table or list of vendor links
        # Look for links that point to vendor password pages
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            text = link.get_text(strip=True)

            # Match vendor password page links
            if '/passwords?' in href or '/passwords/' in href:
                if text and len(text) > 1:
                    # Make absolute URL
                    if href.startswith('/'):
                        href = f"https://cirt.net{href}"
                    elif not href.startswith('http'):
                        href = f"https://cirt.net/{href}"

                    vendors.append((text, href))

        return vendors

    def _fetch_vendor_credentials(self, vendor_name: str, vendor_url: str) -> List[Credential]:
        """
        Fetch credentials for a specific vendor.

        Args:
            vendor_name: Name of the vendor
            vendor_url: URL to the vendor's password page

        Returns:
            List of Credential objects
        """
        credentials = []

        try:
            response = self.session.get(
                vendor_url,
                timeout=self.config.timeout_seconds,
            )
            response.raise_for_status()

            # Parse the credentials from the page
            creds = self._parse_vendor_page(vendor_name, response.text)
            credentials.extend(creds)

        except requests.RequestException as e:
            logger.debug(f"Failed to fetch {vendor_url}: {e}")

        return credentials

    def _parse_vendor_page(self, vendor_name: str, html: str) -> List[Credential]:
        """
        Parse a vendor's password page.

        Args:
            vendor_name: Name of the vendor
            html: HTML content of the vendor's page

        Returns:
            List of Credential objects
        """
        credentials = []
        soup = BeautifulSoup(html, 'html.parser')

        # CIRT.net typically displays credentials in tables
        tables = soup.find_all('table')

        for table in tables:
            rows = table.find_all('tr')

            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) < 3:
                    continue

                # Try to extract product, username, password
                # Column order may vary, try common patterns
                cell_texts = [c.get_text(strip=True) for c in cells]

                # Skip header rows
                if any(h.lower() in ['username', 'password', 'product'] for h in cell_texts):
                    continue

                # Try to identify columns
                cred = self._extract_credential_from_row(vendor_name, cell_texts)
                if cred:
                    credentials.append(cred)

        # Also look for credentials in other formats (lists, divs)
        creds_from_text = self._extract_credentials_from_text(vendor_name, soup)
        credentials.extend(creds_from_text)

        return credentials

    def _extract_credential_from_row(
        self,
        vendor_name: str,
        cells: List[str],
    ) -> Optional[Credential]:
        """
        Extract a credential from table row cells.

        Args:
            vendor_name: Vendor name
            cells: List of cell text values

        Returns:
            Credential if extracted, None otherwise
        """
        if len(cells) < 2:
            return None

        # Heuristics to identify columns
        username = None
        password = None
        product = None

        # Common patterns for cells
        for i, cell in enumerate(cells):
            cell_lower = cell.lower()

            # Skip empty cells
            if not cell or cell in ['-', 'n/a', 'none']:
                continue

            # Username indicators
            if 'admin' in cell_lower or 'root' in cell_lower or '@' in cell:
                if username is None:
                    username = cell

            # Password/default indicators
            elif 'password' in cell_lower or 'default' in cell_lower:
                if password is None and cell.lower() != 'password':
                    password = cell

            # Model/Product name
            elif len(cell) > 3 and not cell.isdigit():
                if product is None:
                    product = cell

        # If we still don't have credentials, try positional
        if len(cells) >= 3 and (username is None or password is None):
            # Assume: Product, Username, Password
            product = product or cells[0]
            username = username or cells[1]
            password = password or cells[2]

        if not username and not password:
            return None

        # Create credential
        category = self.determine_category(vendor_name, product)
        protocols = self.determine_protocols(product)

        return Credential(
            username=username or "",
            password=password or "",
            priority=35,  # Lower priority than builtin and defaultcreds
            source=CredSource.EXTERNAL,
            vendor=self.normalize_vendor(vendor_name),
            product=self.normalize_product(product),
            category=category,
            protocols=protocols,
            description=f"From CIRT.net: {vendor_name}",
            tags=["cirt", "external"],
        )

    def _extract_credentials_from_text(
        self,
        vendor_name: str,
        soup: BeautifulSoup,
    ) -> List[Credential]:
        """
        Extract credentials from free-form text.

        Args:
            vendor_name: Vendor name
            soup: BeautifulSoup object of the page

        Returns:
            List of Credential objects
        """
        credentials = []

        # Get all text content
        text = soup.get_text()

        # Common patterns for credentials
        patterns = [
            # username:password
            r'(?:user(?:name)?|login)\s*[:=]\s*([^\s,;]+).*?(?:pass(?:word)?)\s*[:=]\s*([^\s,;]+)',
            # admin/admin format
            r'default\s+(?:credentials?|login)\s*[:=]?\s*([^\s/]+)/([^\s]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    username, password = match
                    if username and password:
                        category = self.determine_category(vendor_name)
                        protocols = self.determine_protocols()

                        cred = Credential(
                            username=username.strip(),
                            password=password.strip(),
                            priority=30,
                            source=CredSource.EXTERNAL,
                            vendor=self.normalize_vendor(vendor_name),
                            category=category,
                            protocols=protocols,
                            description=f"From CIRT.net: {vendor_name}",
                            tags=["cirt", "external", "text-extracted"],
                        )
                        credentials.append(cred)

        return credentials

    def parse(self, raw_data: Any) -> List[Credential]:
        """
        Parse raw data into Credential objects.

        For CIRT, this is handled by the specialized parsing methods.

        Args:
            raw_data: Not used for CIRT (scraping-based)

        Returns:
            Empty list (parsing happens in fetch)
        """
        return []


def create_cirt_source(config: SourceConfig = None) -> CIRTSource:
    """Factory function to create CIRT source."""
    return CIRTSource(config=config)
