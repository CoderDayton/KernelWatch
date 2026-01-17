"""Windows Update Catalog source collector."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

from bs4 import BeautifulSoup

from kernel_watch.sources.base import Source, SourceResult
from kernel_watch.utils.http import RateLimitedClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

CATALOG_BASE = "https://www.catalog.update.microsoft.com"
SEARCH_URL = f"{CATALOG_BASE}/Search.aspx"
DOWNLOAD_URL = f"{CATALOG_BASE}/DownloadDialog.aspx"


class WUCatalogSource(Source):
    """Scraper for Windows Update Catalog."""

    def __init__(self, queries: list[str] | None = None) -> None:
        self._queries = queries or ["driver", "firmware", "bios", "utility"]
        self._client = RateLimitedClient()
        # Polite rate limiting
        self._client.set_rate_limit("www.catalog.update.microsoft.com", 0.5, burst=2)

    @property
    def name(self) -> str:
        return "WindowsUpdateCatalog"

    @property
    def rate_limit_requests(self) -> int:
        return 20

    @property
    def rate_limit_window_seconds(self) -> int:
        return 60

    async def fetch(
        self,
        query: str | None = None,
        limit: int = 10,
        **kwargs: Any,
    ) -> SourceResult:
        """Fetch drivers matching query."""
        result = SourceResult(source_name=self.name)
        queries = [query] if query else self._queries

        for q in queries:
            try:
                # 1. Search
                update_ids = await self._search(q, limit)

                # 2. Get download links
                # (batching is possible but let's do one by one for simplicity/reliability)
                for uid, title in update_ids:
                    try:
                        urls = await self._get_download_links(uid)
                        if urls:
                            result.download_urls.extend(urls)
                            result.metadata.setdefault("drivers", []).append(
                                {"title": title, "update_id": uid, "urls": urls}
                            )
                    except Exception as e:
                        result.errors.append(f"Error fetching links for {uid}: {e}")

            except Exception as e:
                result.errors.append(f"Error searching '{q}': {e}")

        return result

    def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """Fetch new drivers."""

        async def _generator() -> AsyncIterator[SourceResult]:
            # WUC doesn't support "since" parameter easily without parsing dates from the table
            # which format varies. For now, we perform a standard fetch.
            res = await self.fetch(limit=5)
            if res.total_items > 0:
                yield res

        return _generator()

    async def _search(self, query: str, limit: int) -> list[tuple[str, str]]:
        """Search catalog and return list of (updateId, title)."""
        response = await self._client.get(SEARCH_URL, params={"q": query})
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "lxml")
        results = []

        # The catalog table structure is complex, usually involving a grid
        # We look for rows with update ids.
        # IDs are often in inputs like <input id="..._updateId" value="...">

        # This is a heuristic based on typical structure
        rows = soup.select("tr[id^='ctl00_catalogBody_updateList_ctl']")

        for row in rows[:limit]:
            # Extract ID
            inputs = row.select("input[id$='_updateId']")
            if not inputs:
                continue

            uid_raw = inputs[0].get("value")
            uid = str(uid_raw) if uid_raw else ""

            # Extract title
            title_cell = row.select_one("td.resultsColumn")
            title = title_cell.get_text(strip=True) if title_cell else "Unknown"

            if uid:
                results.append((uid, title))

        return results

    async def _get_download_links(self, update_id: str) -> list[str]:
        """Get download links for an update ID."""
        # The download dialog is populated via AJAX or embedded JS
        response = await self._client.get(
            DOWNLOAD_URL,
            params={
                "updateIds": (
                    f"[{json.dumps(update_id)}]" if not update_id.startswith("[") else update_id
                )
            },
        )
        # Note: The real URL expects `updateIds` to be a JSON array string sometimes
        # Let's try raw ID first
        # (usually `updateIds` param takes `[{"size":0,"languages":"","uid":"..."}]`)
        # Actually, simpler: `updateIds=[{"uid":"..."}]`

        # We might need to construct the payload carefully.
        # For this implementation, we'll placeholder the complex interaction
        # because the WU Catalog is notoriously hard to scrape without JS execution.

        # Alternative: Regex search for http .cab/.exe links in the response text
        # (often they are embedded in script tags)

        links = []
        # Regex for .cab, .exe, .msi links
        pattern = re.compile(r'http[s]?://[^"\']+\.(?:cab|exe|msi|sys)', re.IGNORECASE)
        for match in pattern.finditer(response.text):
            links.append(match.group(0))

        return list(set(links))

    async def close(self) -> None:
        await self._client.close()
