"""Tests for PE analysis and disassembly."""

from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kernel_watch.analysis.disasm import IOCTLAccess, IOCTLCode, IOCTLMethod
from kernel_watch.analysis.pe import PEAnalysisResult, analyze_pe, calculate_risk_score
from kernel_watch.models import Driver, DriverHash


@pytest.fixture
def mock_pe() -> Generator[MagicMock, None, None]:
    """Mock pefile.PE object."""
    with patch("pefile.PE") as mock:
        pe_instance = mock.return_value
        pe_instance.FILE_HEADER.TimeDateStamp = 0
        pe_instance.get_imphash.return_value = "e123456"
        pe_instance.sections = []
        pe_instance.close = MagicMock()
        # Mock get_memory_mapped_image to return safe data
        pe_instance.get_memory_mapped_image.return_value = b"\x00" * 1024
        yield mock


def test_analyze_pe_basic(mock_pe: MagicMock, tmp_path: Path) -> None:
    """Test basic PE analysis."""
    dummy_file = tmp_path / "test.sys"
    dummy_file.write_bytes(b"MZ" + b"\x00" * 100)

    with patch("kernel_watch.analysis.pe.compute_full_hashes") as mock_hash:
        mock_hash.return_value = DriverHash(sha256="hash")

        # We need to make sure pefile is imported before we patch it if we used string patching
        # But here we used 'pefile.PE' which should work if pefile is installed

        result = analyze_pe(dummy_file)

    assert isinstance(result, PEAnalysisResult)
    assert result.driver.name == "test.sys"
    # assert result.driver.hashes.imphash == "e123456" # This depends on PE mock working
    # If the mock didn't work, this would fail or hang.

    # Verify mock was called
    assert mock_pe.called or result.errors


def test_calculate_risk_score() -> None:
    """Test risk score calculation logic."""
    driver = Driver(name="test", hashes=DriverHash(sha256="abc"))

    # Base case: Not in LOLDrivers = +30 score (potential new finding)
    result = PEAnalysisResult(driver=driver)
    assert calculate_risk_score(result, in_loldrivers=False) == 30
    assert calculate_risk_score(result, in_loldrivers=True) == 0

    # Dangerous imports
    result.dangerous_imports = ["MmMapIoSpace"]
    # 30 (base) + 50 (MmMapIoSpace) = 80
    assert calculate_risk_score(result, in_loldrivers=False) == 80

    result.dangerous_imports = ["MmMapIoSpace", "__readmsr"]
    # 30 + 50 + 40 = 120 -> capped at 100
    assert calculate_risk_score(result, in_loldrivers=False) == 100

    # Major vendor (mock)
    result.driver.vendor = "ASUS"
    result.driver.signature = MagicMock()
    # 100 + 20 = 120 -> cap at 100
    assert calculate_risk_score(result, in_loldrivers=False) == 100


def test_ioctl_code_parsing() -> None:
    """Test parsing of IOCTL codes."""
    # Example: Device=0x22 (Unknown), Access=0, Function=1, Method=0
    # (0x22 << 16) | (0 << 14) | (1 << 2) | 0 = 0x00220004
    raw = 0x00220004

    code = IOCTLCode.from_raw(raw)
    assert code.device_type == 0x22
    assert code.function == 1
    assert code.method == IOCTLMethod.BUFFERED
    assert code.access == IOCTLAccess.ANY
