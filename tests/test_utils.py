"""Unit tests for utility modules."""

import hashlib
import tempfile
from pathlib import Path

import pytest

from kernel_watch.utils.hashing import compute_hashes, compute_hashes_from_bytes
from kernel_watch.utils.http import RateLimitedClient, RateLimiter


def test_compute_hashes_from_bytes() -> None:
    """Test hash computation from bytes."""
    data = b"test data"
    hashes = compute_hashes_from_bytes(data)

    assert hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert hashes.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324
    assert hashes.md5 == hashlib.md5(data).hexdigest()  # noqa: S324


def test_compute_hashes_file() -> None:
    """Test hash computation from file."""
    data = b"file content"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = Path(f.name)

    try:
        hashes = compute_hashes(path)
        assert hashes.sha256 == hashlib.sha256(data).hexdigest()
        assert hashes.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324
        assert hashes.md5 == hashlib.md5(data).hexdigest()  # noqa: S324
    finally:
        path.unlink()


@pytest.mark.asyncio
async def test_rate_limiter() -> None:
    """Test token bucket rate limiter."""
    limiter = RateLimiter(max_tokens=2, refill_rate=10.0)

    # First 2 should be instant
    await limiter.acquire(1)
    await limiter.acquire(1)

    # Next one should wait (but hard to test exact timing in unit test without mocks)
    # Just verify it doesn't hang forever
    await limiter.acquire(1)


@pytest.mark.asyncio
async def test_http_client_context() -> None:
    """Test HTTP client context manager."""
    async with RateLimitedClient() as client:
        assert client._client.is_closed is False
    assert client._client.is_closed is True
