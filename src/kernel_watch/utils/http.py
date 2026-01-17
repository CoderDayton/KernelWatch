"""Rate-limited async HTTP client."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass
class RateLimiter:
    """Token bucket rate limiter."""

    max_tokens: int
    refill_rate: float  # tokens per second
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.max_tokens)
        self._last_refill = asyncio.get_event_loop().time()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary."""
        async with self._lock:
            await self._refill()
            while self._tokens < tokens:
                wait_time = (tokens - self._tokens) / self.refill_rate
                await asyncio.sleep(wait_time)
                await self._refill()
            self._tokens -= tokens

    async def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_tokens, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now


class RateLimitedClient:
    """HTTP client with per-host rate limiting."""

    def __init__(
        self,
        default_rate: float = 1.0,  # requests per second
        default_burst: int = 5,
        timeout: float = 30.0,
        user_agent: str = "DriverSearch/0.1.0",
    ) -> None:
        self._default_rate = default_rate
        self._default_burst = default_burst
        self._limiters: dict[str, RateLimiter] = {}
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": user_agent},
            follow_redirects=True,
        )

    def set_rate_limit(
        self,
        host: str,
        requests_per_second: float,
        burst: int | None = None,
    ) -> None:
        """Configure rate limit for a specific host."""
        self._limiters[host] = RateLimiter(
            max_tokens=burst or self._default_burst,
            refill_rate=requests_per_second,
        )

    def _get_limiter(self, url: str) -> RateLimiter:
        """Get or create rate limiter for URL's host."""
        host = httpx.URL(url).host or "default"
        if host not in self._limiters:
            self._limiters[host] = RateLimiter(
                max_tokens=self._default_burst,
                refill_rate=self._default_rate,
            )
        return self._limiters[host]

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Rate-limited GET request."""
        limiter = self._get_limiter(url)
        await limiter.acquire()
        return await self._client.get(url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        *,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Rate-limited POST request."""
        limiter = self._get_limiter(url)
        await limiter.acquire()
        return await self._client.post(url, json=json, data=data, headers=headers)

    async def download(
        self,
        url: str,
        dest_path: str,
        *,
        chunk_size: int = 8192,
    ) -> int:
        """Download file with rate limiting. Returns bytes written."""
        limiter = self._get_limiter(url)
        await limiter.acquire()

        total_bytes = 0
        async with self._client.stream("GET", url) as response:
            response.raise_for_status()
            with open(dest_path, "wb") as f:
                async for chunk in response.aiter_bytes(chunk_size):
                    f.write(chunk)
                    total_bytes += len(chunk)
        return total_bytes

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> RateLimitedClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
