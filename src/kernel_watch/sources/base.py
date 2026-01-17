"""Abstract base for data source collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@dataclass(slots=True)
class SourceResult:
    """Result from a source query."""

    source_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    driver_hashes: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there were any errors."""
        return len(self.errors) > 0

    @property
    def total_items(self) -> int:
        """Total number of items found."""
        return len(self.driver_hashes) + len(self.cve_ids) + len(self.download_urls)


class Source(ABC):
    """Abstract base class for data sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name."""
        ...

    @property
    @abstractmethod
    def rate_limit_requests(self) -> int:
        """Max requests per rate_limit_window."""
        ...

    @property
    @abstractmethod
    def rate_limit_window_seconds(self) -> int:
        """Rate limit window in seconds."""
        ...

    @abstractmethod
    async def fetch(self, **kwargs: Any) -> SourceResult:
        """Fetch data from the source."""
        ...

    @abstractmethod
    def fetch_incremental(
        self,
        since: datetime | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[SourceResult]:
        """Fetch new data since last check."""
        ...

    async def health_check(self) -> bool:
        """Check if source is accessible."""
        return True
