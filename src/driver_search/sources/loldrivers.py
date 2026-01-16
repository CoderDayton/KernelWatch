"""LOLDrivers GitHub repository source collector."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import yaml

from driver_search.sources.base import Source, SourceResult
from driver_search.utils.http import RateLimitedClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

LOLDRIVERS_REPO = "magicsword-io/LOLDrivers"
LOLDRIVERS_RAW_BASE = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main"
GITHUB_API_BASE = "https://api.github.com"


class LOLDriversSource(Source):
    """LOLDrivers GitHub repository collector."""

    def __init__(self, github_token: str | None = None) -> None:
        self._github_token = github_token
        self._client = RateLimitedClient()
        # GitHub rate limits: 5000/hr authenticated, 60/hr unauthenticated
        rate = 1.0 if github_token else 0.01
        self._client.set_rate_limit("api.github.com", rate, burst=10)
        self._client.set_rate_limit("raw.githubusercontent.com", 2.0, burst=20)

    @property
    def name(self) -> str:
        return "LOLDrivers"

    @property
    def rate_limit_requests(self) -> int:
        return 5000 if self._github_token else 60

    @property
    def rate_limit_window_seconds(self) -> int:
        return 3600

    def _get_headers(self) -> dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    async def fetch(self, **kwargs: Any) -> SourceResult:
        """Fetch all driver hashes from LOLDrivers."""
        result = SourceResult(source_name=self.name)

        try:
            # Get list of YAML files in the yaml directory
            files = await self._list_yaml_files()

            for file_path in files:
                try:
                    driver_data = await self._fetch_driver_yaml(file_path)
                    hashes = self._extract_hashes(driver_data)
                    result.driver_hashes.extend(hashes)

                    # Store metadata
                    if hashes:
                        result.metadata.setdefault("drivers", []).append(
                            {
                                "name": driver_data.get("Name", file_path),
                                "category": driver_data.get("Category", "unknown"),
                                "hashes": hashes,
                            }
                        )
                except Exception as e:
                    result.errors.append(f"Error processing {file_path}: {e}")

        except Exception as e:
            result.errors.append(f"Error fetching file list: {e}")

        # Deduplicate hashes
        result.driver_hashes = list(dict.fromkeys(result.driver_hashes))
        return result

    async def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """Fetch newly added drivers since last check."""
        if since is None:
            since = datetime.now() - timedelta(days=30)

        try:
            commits = await self._get_recent_commits(since)

            for commit in commits:
                result = SourceResult(source_name=self.name)
                result.metadata["commit_sha"] = commit["sha"]
                result.metadata["commit_date"] = commit["date"]
                result.metadata["commit_message"] = commit["message"]

                # Get files changed in this commit
                changed_files = await self._get_commit_files(commit["sha"])

                for file_path in changed_files:
                    if file_path.endswith(".yaml") and "yaml/" in file_path:
                        try:
                            driver_data = await self._fetch_driver_yaml(file_path)
                            hashes = self._extract_hashes(driver_data)
                            result.driver_hashes.extend(hashes)
                        except Exception as e:
                            result.errors.append(f"Error processing {file_path}: {e}")

                if result.driver_hashes:
                    yield result

        except Exception as e:
            result = SourceResult(source_name=self.name)
            result.errors.append(f"Error fetching commits: {e}")
            yield result

    async def _list_yaml_files(self) -> list[str]:
        """List all YAML files in the drivers directory."""
        url = f"{GITHUB_API_BASE}/repos/{LOLDRIVERS_REPO}/contents/yaml/drivers"
        response = await self._client.get(url, headers=self._get_headers())
        response.raise_for_status()

        files = response.json()
        return [f["path"] for f in files if f["name"].endswith(".yaml")]

    async def _fetch_driver_yaml(self, file_path: str) -> dict[str, Any]:
        """Fetch and parse a driver YAML file."""
        url = f"{LOLDRIVERS_RAW_BASE}/{file_path}"
        response = await self._client.get(url)
        response.raise_for_status()

        return yaml.safe_load(response.text)

    async def _get_recent_commits(self, since: datetime) -> list[dict[str, Any]]:
        """Get commits to the yaml directory since a date."""
        url = f"{GITHUB_API_BASE}/repos/{LOLDRIVERS_REPO}/commits"
        params = {
            "path": "yaml",
            "since": since.isoformat(),
            "per_page": "100",
        }

        response = await self._client.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()

        commits = response.json()
        return [
            {
                "sha": c["sha"],
                "date": c["commit"]["committer"]["date"],
                "message": c["commit"]["message"],
            }
            for c in commits
        ]

    async def _get_commit_files(self, sha: str) -> list[str]:
        """Get list of files changed in a commit."""
        url = f"{GITHUB_API_BASE}/repos/{LOLDRIVERS_REPO}/commits/{sha}"
        response = await self._client.get(url, headers=self._get_headers())
        response.raise_for_status()

        data = response.json()
        return [f["filename"] for f in data.get("files", [])]

    def _extract_hashes(self, driver_data: dict[str, Any]) -> list[str]:
        """Extract SHA256 hashes from driver YAML data."""
        hashes: list[str] = []

        samples = driver_data.get("KnownVulnerableSamples", [])
        for sample in samples:
            if sha256 := sample.get("SHA256"):
                hashes.append(sha256.lower())

        return hashes

    async def get_driver_by_hash(self, sha256: str) -> dict[str, Any] | None:
        """Look up a specific driver by hash."""
        # This is a simplistic implementation - in production you'd want an index
        result = await self.fetch()
        for driver in result.metadata.get("drivers", []):
            if sha256.lower() in [h.lower() for h in driver.get("hashes", [])]:
                return driver
        return None

    async def health_check(self) -> bool:
        """Check if GitHub API is accessible."""
        try:
            url = f"{GITHUB_API_BASE}/repos/{LOLDRIVERS_REPO}"
            response = await self._client.get(url, headers=self._get_headers())
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.close()
