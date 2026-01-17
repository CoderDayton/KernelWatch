"""Tests for data sources."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from driver_search.sources.loldrivers import LOLDriversSource
from driver_search.sources.nvd import NVDSource


@pytest.mark.asyncio
async def test_nvd_source_fetch():
    """Test NVD fetch logic."""
    with patch(
        "driver_search.utils.http.RateLimitedClient.get", new_callable=AsyncMock
    ) as mock_get:
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "metrics": {},
                        "references": [],
                        "weaknesses": [],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        source = NVDSource(api_key="test")
        result = await source.fetch(keyword="driver")

        assert len(result.cve_ids) == 1
        assert result.cve_ids[0] == "CVE-2024-1234"
        assert not result.has_errors


@pytest.mark.asyncio
async def test_loldrivers_source_fetch():
    """Test LOLDrivers fetch logic."""
    with patch("driver_search.sources.loldrivers.LOLDriversSource._list_yaml_files") as mock_list:
        with patch(
            "driver_search.sources.loldrivers.LOLDriversSource._fetch_driver_yaml"
        ) as mock_fetch:
            mock_list.return_value = ["test.yaml"]
            mock_fetch.return_value = {
                "Name": "Vulnerable.sys",
                "KnownVulnerableSamples": [{"SHA256": "aabbcc"}],
            }

            source = LOLDriversSource()
            result = await source.fetch()

            assert len(result.driver_hashes) == 1
            assert result.driver_hashes[0] == "aabbcc"
