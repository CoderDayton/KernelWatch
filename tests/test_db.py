"""Tests for database operations."""

from datetime import datetime
from pathlib import Path

import pytest

from kernel_watch.db import get_database
from kernel_watch.models import AnalysisResult, Driver, DriverHash, RiskLevel


@pytest.mark.asyncio
async def test_driver_crud(tmp_path: Path) -> None:
    """Test Create/Read operations for drivers."""
    db_path = tmp_path / "test.db"

    async with get_database(db_path) as db:
        driver = Driver(
            name="test.sys",
            hashes=DriverHash(sha256="123", sha1="456", md5="789"),
            vendor="TestVendor",
            first_seen=datetime.now(),
        )

        # Create
        await db.save_driver(driver)

        # Read
        saved = await db.get_driver("123")
        assert saved is not None
        assert saved.name == "test.sys"
        assert saved.vendor == "TestVendor"

        # Exists
        assert await db.driver_exists("123")
        assert not await db.driver_exists("999")


@pytest.mark.asyncio
async def test_analysis_result_save(tmp_path: Path) -> None:
    """Test saving analysis results."""
    db_path = tmp_path / "test.db"

    async with get_database(db_path) as db:
        driver = Driver(name="vuln.sys", hashes=DriverHash(sha256="abc"))
        result = AnalysisResult(
            driver=driver, risk_level=RiskLevel.HIGH, risk_score=80, in_loldrivers=True
        )

        await db.save_analysis_result(result)

        stats = await db.get_stats()
        assert stats["analyses"] == 1
        assert stats["drivers"] == 1


@pytest.mark.asyncio
async def test_loldrivers_hashes(tmp_path: Path) -> None:
    """Test LOLDrivers hash operations."""
    db_path = tmp_path / "test.db"

    async with get_database(db_path) as db:
        await db.save_loldrivers_hash("aabbcc", "known.sys", "vulnerable")

        assert await db.is_in_loldrivers("aabbcc")
        assert await db.is_in_loldrivers("AABBCC")  # Case insensitive
        assert not await db.is_in_loldrivers("ddeeff")
