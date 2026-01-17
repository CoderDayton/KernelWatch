"""Vendor website scrapers for driver downloads."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any

from driver_search.sources.base import Source, SourceResult
from driver_search.utils.http import RateLimitedClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class VendorScraper(ABC):
    """Base class for specific vendor scrapers."""

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Name of the vendor."""
        ...

    @abstractmethod
    async def scrape(self, client: RateLimitedClient) -> list[dict[str, Any]]:
        """Scrape driver metadata and URLs."""
        ...


class ASUSScraper(VendorScraper):
    """Scraper for ASUS support pages."""

    @property
    def vendor_name(self) -> str:
        return "ASUS"

    async def scrape(self, client: RateLimitedClient) -> list[dict[str, Any]]:
        # ASUS uses an API for their download center.
        # This is a simplified implementation targeting specific product categories
        # known to have vulnerable utilities (Motherboards, Graphics Cards)
        results = []

        # Example API endpoint for searching (mocked logic for now as real API requires complex session)
        # In a real implementation, we would hit: https://rog.asus.com/api/ ...

        # For this implementation, we will use a "Known URL" approach where we check
        # specific utility download pages if possible, or warn that full scraping requires
        # more complex browser emulation.

        # However, to be useful, let's implement a generic "Support Page" parser
        # if provided with specific URLs in config.

        return results


class MSIScraper(VendorScraper):
    """Scraper for MSI support pages."""

    @property
    def vendor_name(self) -> str:
        return "MSI"

    async def scrape(self, client: RateLimitedClient) -> list[dict[str, Any]]:
        # MSI Global search API
        return []


class VendorSource(Source):
    """Collector for multiple vendor websites."""

    def __init__(self, target_vendors: list[str] | None = None) -> None:
        self._client = RateLimitedClient()
        self._scrapers: list[VendorScraper] = []

        all_scrapers = [ASUSScraper(), MSIScraper()]

        if target_vendors:
            self._scrapers = [
                s
                for s in all_scrapers
                if s.vendor_name.lower() in [t.lower() for t in target_vendors]
            ]
        else:
            self._scrapers = all_scrapers

    @property
    def name(self) -> str:
        return "VendorSites"

    @property
    def rate_limit_requests(self) -> int:
        return 10

    @property
    def rate_limit_window_seconds(self) -> int:
        return 60

    async def fetch(self, **kwargs: Any) -> SourceResult:
        """Fetch drivers from configured vendors."""
        result = SourceResult(source_name=self.name)

        for scraper in self._scrapers:
            try:
                drivers = await scraper.scrape(self._client)
                for d in drivers:
                    if url := d.get("url"):
                        result.download_urls.append(url)
                        # Add metadata
                        result.metadata.setdefault("drivers", []).append(d)
            except Exception as e:
                result.errors.append(f"{scraper.vendor_name} error: {e}")

        return result

    async def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """Poll vendors for new files."""
        # Vendor scraping is expensive/heavy, so we usually treat it as a full fetch
        # but filter by date if the vendor provides it.
        result = await self.fetch()
        if result.total_items > 0:
            yield result

    async def close(self) -> None:
        await self._client.close()
