"""Integration tests for KernelWatch."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from kernel_watch.cli import app
from kernel_watch.config import get_settings, reset_settings
from kernel_watch.db import get_database

runner = CliRunner()


@pytest.fixture
def mock_db(tmp_path: Path) -> Path:
    """Setup a temporary database."""
    reset_settings()
    settings = get_settings()
    settings.output.db_path = tmp_path / "test.db"
    settings.ensure_directories()
    return settings.output.db_path


@pytest.mark.asyncio
async def test_db_init(mock_db: Path) -> None:
    """Test database initialization."""
    async with get_database() as db:
        stats = await db.get_stats()
        assert stats["drivers"] == 0
        assert stats["analyses"] == 0


def test_cli_help() -> None:
    """Test CLI help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Vulnerable driver research tooling" in result.stdout


def test_cli_sync_loldrivers(mock_db: Path) -> None:
    """Test sync-loldrivers command (mocked)."""
    with patch(
        "kernel_watch.analyzer.Analyzer.sync_loldrivers", new_callable=AsyncMock
    ) as mock_sync:
        mock_sync.return_value = 10

        result = runner.invoke(app, ["sync-loldrivers"])
        assert result.exit_code == 0
        assert "Successfully synced 10 driver hashes" in result.stdout


def test_cli_dashboard_json(mock_db: Path) -> None:
    """Test dashboard JSON output."""
    # Initialize DB with some dummy data for the dashboard to read
    # We can use the mock_db fixture which sets up the path, but the DB is empty
    # dashboard command reads from DB.

    result = runner.invoke(app, ["dashboard", "--json"])
    assert result.exit_code == 0
    assert "drivers" in result.stdout
    assert "critical_risk" in result.stdout
    assert "{" in result.stdout


@pytest.mark.asyncio
async def test_save_driver(mock_db: Path) -> None:
    """Test saving a driver to DB."""
    from kernel_watch.models import Driver, DriverHash

    driver = Driver(
        name="test.sys",
        hashes=DriverHash(sha256="A" * 64, sha1="B" * 40, md5="C" * 32),
        vendor="TestVendor",
    )

    async with get_database() as db:
        await db.save_driver(driver)

        saved = await db.get_driver(driver.hashes.sha256)
        assert saved is not None
        assert saved.name == "test.sys"
        assert saved.vendor == "TestVendor"
