"""NVD (National Vulnerability Database) source collector."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from kernel_watch.models import CVEEntry
from kernel_watch.sources.base import Source, SourceResult
from kernel_watch.utils.http import RateLimitedClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDSource(Source):
    """NVD CVE feed collector for driver-related vulnerabilities."""

    def __init__(
        self,
        api_key: str | None = None,
        keywords: list[str] | None = None,
    ) -> None:
        self._api_key = api_key
        self._keywords = keywords or [
            "motherboard",
            "overclock",
            "hardware monitor",
            "tuning utility",
            "driver privilege",
            "kernel driver",
        ]
        self._client = RateLimitedClient()
        # NVD rate limits: 50/30s with key, 5/30s without
        rate = 1.5 if api_key else 0.15
        self._client.set_rate_limit("services.nvd.nist.gov", rate, burst=5)

    @property
    def name(self) -> str:
        return "NVD"

    @property
    def rate_limit_requests(self) -> int:
        return 50 if self._api_key else 5

    @property
    def rate_limit_window_seconds(self) -> int:
        return 30

    async def fetch(
        self,
        keyword: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        **kwargs: Any,
    ) -> SourceResult:
        """Fetch CVEs matching criteria."""
        result = SourceResult(source_name=self.name)

        keywords_to_search = [keyword] if keyword else self._keywords

        for kw in keywords_to_search:
            try:
                cves = await self._search_keyword(kw, start_date, end_date)
                result.cve_ids.extend(cve.cve_id for cve in cves)
                result.metadata.setdefault("cve_entries", []).extend(
                    self._cve_to_dict(cve) for cve in cves
                )
            except Exception as e:
                result.errors.append(f"Error searching '{kw}': {e}")

        # Deduplicate
        result.cve_ids = list(dict.fromkeys(result.cve_ids))
        return result

    def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """Fetch new CVEs since last check."""

        async def _generator() -> AsyncIterator[SourceResult]:
            start_date = datetime.now() - timedelta(days=7) if since is None else since

            for keyword in self._keywords:
                result = await self.fetch(
                    keyword=keyword,
                    start_date=start_date,
                    end_date=datetime.now(),
                )
                if result.total_items > 0:
                    yield result

        return _generator()

    async def _search_keyword(
        self,
        keyword: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[CVEEntry]:
        """Search NVD for a specific keyword."""
        params: dict[str, str] = {"keywordSearch": keyword}

        if start_date:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000")
        if end_date:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999")

        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        response = await self._client.get(NVD_API_BASE, params=params, headers=headers)
        response.raise_for_status()

        data = response.json()
        return self._parse_response(data)

    def _parse_response(self, data: dict[str, Any]) -> list[CVEEntry]:
        """Parse NVD API response into CVEEntry objects."""
        entries: list[CVEEntry] = []

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get dates
            published = datetime.fromisoformat(cve_data.get("published", "").replace("Z", "+00:00"))
            modified = datetime.fromisoformat(
                cve_data.get("lastModified", "").replace("Z", "+00:00")
            )

            # Get CVSS score
            cvss_score = None
            cvss_vector = None
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(version):
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # Get references
            references = tuple(
                ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")
            )

            # Get CWE IDs
            cwe_ids: list[str] = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value", ""))

            entries.append(
                CVEEntry(
                    cve_id=cve_id,
                    description=description,
                    published=published,
                    modified=modified,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    references=references,
                    cwe_ids=tuple(cwe_ids),
                )
            )

        return entries

    def _cve_to_dict(self, cve: CVEEntry) -> dict[str, Any]:
        """Convert CVEEntry to dictionary for metadata storage."""
        return {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published": cve.published.isoformat(),
            "modified": cve.modified.isoformat(),
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "references": list(cve.references),
            "cwe_ids": list(cve.cwe_ids),
        }

    async def health_check(self) -> bool:
        """Check if NVD API is accessible."""
        try:
            response = await self._client.get(
                NVD_API_BASE,
                params={"keywordSearch": "test", "resultsPerPage": "1"},
            )
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.close()
