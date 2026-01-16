"""Configuration management using pydantic-settings."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class APIKeys(BaseSettings):
    """API key configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DRIVER_SEARCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    nvd_api_key: SecretStr | None = Field(
        default=None,
        description="NVD API key for higher rate limits",
    )
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        description="VirusTotal API key",
    )
    github_token: SecretStr | None = Field(
        default=None,
        description="GitHub token for API access",
    )


class MonitoringSettings(BaseSettings):
    """Monitoring configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DRIVER_SEARCH_MONITOR_",
        extra="ignore",
    )

    nvd_keywords: list[str] = Field(
        default_factory=lambda: [
            "motherboard",
            "overclock",
            "hardware monitor",
            "tuning utility",
            "bios update",
            "rgb control",
            "fan control",
        ],
        description="Keywords to search in NVD",
    )
    poll_interval_hours: Annotated[int, Field(ge=1, le=168)] = Field(
        default=6,
        description="Hours between polling cycles",
    )
    vendor_urls: list[str] = Field(
        default_factory=list,
        description="Vendor download page URLs to monitor",
    )


class AnalysisSettings(BaseSettings):
    """Analysis configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DRIVER_SEARCH_ANALYSIS_",
        extra="ignore",
    )

    auto_download: bool = Field(
        default=False,
        description="Automatically download drivers for analysis",
    )
    max_file_size_mb: Annotated[int, Field(ge=1, le=500)] = Field(
        default=50,
        description="Maximum driver file size to analyze",
    )
    disassemble_depth: Annotated[int, Field(ge=0, le=1000)] = Field(
        default=100,
        description="Max instructions to disassemble per function",
    )


class OutputSettings(BaseSettings):
    """Output/storage configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DRIVER_SEARCH_OUTPUT_",
        extra="ignore",
    )

    db_path: Path = Field(
        default=Path("data/drivers.db"),
        description="SQLite database path",
    )
    cache_dir: Path = Field(
        default=Path("data/cache"),
        description="Cache directory for downloaded files",
    )
    reports_dir: Path = Field(
        default=Path("data/reports"),
        description="Output directory for reports",
    )


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="DRIVER_SEARCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_keys: APIKeys = Field(default_factory=APIKeys)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)

    debug: bool = Field(default=False, description="Enable debug mode")
    verbose: bool = Field(default=False, description="Enable verbose output")

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.output.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.output.cache_dir.mkdir(parents=True, exist_ok=True)
        self.output.reports_dir.mkdir(parents=True, exist_ok=True)


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get or create settings instance."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset settings (for testing)."""
    global _settings  # noqa: PLW0603
    _settings = None
