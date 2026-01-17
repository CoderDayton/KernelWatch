"""VirusTotal API source for driver analysis."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from kernel_watch.sources.base import Source, SourceResult
from kernel_watch.utils.http import RateLimitedClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalSource(Source):
    """VirusTotal API for driver hash lookups and hunting."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = RateLimitedClient()
        # VT rate limits: 4/min free, 500/min premium
        # Assume free tier by default
        self._client.set_rate_limit("www.virustotal.com", 4 / 60, burst=4)

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def rate_limit_requests(self) -> int:
        return 4

    @property
    def rate_limit_window_seconds(self) -> int:
        return 60

    def _get_headers(self) -> dict[str, str]:
        """Get headers for VT API requests."""
        return {"x-apikey": self._api_key}

    async def fetch(
        self,
        hashes: list[str] | None = None,
        **kwargs: Any,
    ) -> SourceResult:
        """Fetch information for given hashes."""
        result = SourceResult(source_name=self.name)

        if not hashes:
            return result

        for hash_value in hashes:
            try:
                file_info = await self.lookup_hash(hash_value)
                if file_info:
                    result.metadata.setdefault("files", {})[hash_value] = file_info
                    result.driver_hashes.append(hash_value)
            except Exception as e:
                result.errors.append(f"Error looking up {hash_value}: {e}")

        return result

    def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """VT doesn't support incremental fetch without LiveHunt (premium)."""

        async def _generator() -> AsyncIterator[SourceResult]:
            # This is a no-op for free tier
            result = SourceResult(source_name=self.name)
            result.errors.append("Incremental fetch requires VT Premium (LiveHunt)")
            yield result

        return _generator()

    async def lookup_hash(self, hash_value: str) -> dict[str, Any] | None:
        """Look up a file by hash."""
        url = f"{VT_API_BASE}/files/{hash_value}"
        response = await self._client.get(url, headers=self._get_headers())

        if response.status_code == 404:
            return None

        response.raise_for_status()
        result_data: dict[str, Any] = cast("dict[str, Any]", response.json())
        return self._parse_file_response(result_data)

    async def get_file_behavior(self, hash_value: str) -> dict[str, Any] | None:
        """Get behavioral analysis for a file."""
        url = f"{VT_API_BASE}/files/{hash_value}/behaviour_summary"
        response = await self._client.get(url, headers=self._get_headers())

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return cast("dict[str, Any] | None", response.json().get("data"))

    async def search_drivers(
        self,
        query: str = "type:peexe tag:signed-driver",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for drivers matching criteria."""
        url = f"{VT_API_BASE}/intelligence/search"
        params = {"query": query, "limit": str(limit)}

        response = await self._client.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()

        data = response.json()
        results: list[dict[str, Any]] = [
            self._parse_file_response(item) for item in data.get("data", [])
        ]
        return results

    def _parse_file_response(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse VT file response into normalized format."""
        attrs = data.get("data", data).get("attributes", data.get("attributes", {}))

        stats = attrs.get("last_analysis_stats", {})
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())

        # Extract signature info
        signature = None
        if sig_info := attrs.get("signature_info"):
            signature = {
                "signer": sig_info.get("subject", ""),
                "issuer": sig_info.get("issuer", ""),
                "valid": sig_info.get("verified") == "Signed",
            }

        return {
            "sha256": attrs.get("sha256", ""),
            "sha1": attrs.get("sha1", ""),
            "md5": attrs.get("md5", ""),
            "file_name": attrs.get("meaningful_name", attrs.get("name", "")),
            "file_size": attrs.get("size", 0),
            "file_type": attrs.get("type_description", ""),
            "detections": detections,
            "total_engines": total,
            "detection_ratio": f"{detections}/{total}" if total else "0/0",
            "signature": signature,
            "first_seen": attrs.get("first_submission_date"),
            "last_seen": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", []),
            "type_tags": attrs.get("type_tags", []),
        }

    async def health_check(self) -> bool:
        """Check if VT API is accessible."""
        try:
            # Use empty file hash (SHA256 of empty string) for testing
            empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            url = f"{VT_API_BASE}/files/{empty_hash}"
            response = await self._client.get(url, headers=self._get_headers())
            return response.status_code in (200, 404)  # 404 is OK, means API works
        except Exception:
            return False

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.close()
