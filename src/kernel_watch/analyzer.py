"""Core analyzer orchestrator - coordinates sources, analysis, and persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from kernel_watch.analysis.pe import analyze_pe, calculate_risk_score
from kernel_watch.config import get_settings
from kernel_watch.db import Database
from kernel_watch.models import AnalysisResult, RiskLevel
from kernel_watch.output.loldrivers import generate_loldrivers_filename, generate_loldrivers_yaml
from kernel_watch.sources.loldrivers import LOLDriversSource
from kernel_watch.sources.nvd import NVDSource
from kernel_watch.sources.virustotal import VirusTotalSource

console = Console()


@dataclass
class AnalyzerConfig:
    """Configuration for the analyzer."""

    check_loldrivers: bool = True
    check_virustotal: bool = True
    save_to_db: bool = True
    generate_yaml: bool = False
    yaml_output_dir: Path | None = None


@dataclass
class Analyzer:
    """Main orchestrator for driver analysis."""

    config: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    _db: Database | None = field(default=None, repr=False)
    _loldrivers: LOLDriversSource | None = field(default=None, repr=False)
    _virustotal: VirusTotalSource | None = field(default=None, repr=False)
    _nvd: NVDSource | None = field(default=None, repr=False)
    _loldrivers_hashes: set[str] = field(default_factory=set, repr=False)

    async def initialize(self) -> None:
        """Initialize sources and database connections."""
        settings = get_settings()
        settings.ensure_directories()

        # Initialize database
        self._db = Database()
        await self._db.connect()

        # Initialize sources based on available API keys
        github_token = None
        if settings.api_keys.github_token:
            github_token = settings.api_keys.github_token.get_secret_value()
        self._loldrivers = LOLDriversSource(github_token=github_token)

        nvd_key = None
        if settings.api_keys.nvd_api_key:
            nvd_key = settings.api_keys.nvd_api_key.get_secret_value()
        self._nvd = NVDSource(api_key=nvd_key)

        if settings.api_keys.virustotal_api_key:
            vt_key = settings.api_keys.virustotal_api_key.get_secret_value()
            self._virustotal = VirusTotalSource(api_key=vt_key)

    async def close(self) -> None:
        """Clean up resources."""
        if self._db:
            await self._db.close()
        if self._loldrivers:
            await self._loldrivers.close()
        if self._nvd:
            await self._nvd.close()
        if self._virustotal:
            await self._virustotal.close()

    async def sync_loldrivers(self) -> int:
        """Sync LOLDrivers database and return count of hashes."""
        if not self._loldrivers or not self._db:
            raise RuntimeError("Analyzer not initialized")

        console.print("[cyan]Syncing LOLDrivers database...[/cyan]")

        result = await self._loldrivers.fetch()

        if result.has_errors:
            for error in result.errors:
                console.print(f"[yellow]Warning:[/yellow] {error}")

        # Save hashes to local database
        for driver_info in result.metadata.get("drivers", []):
            name = driver_info.get("name", "unknown")
            category = driver_info.get("category", "vulnerable driver")
            for hash_val in driver_info.get("hashes", []):
                await self._db.save_loldrivers_hash(hash_val, name, category)
                self._loldrivers_hashes.add(hash_val.lower())

        console.print(
            f"[green]Synced {len(result.driver_hashes)} hashes from "
            f"{len(result.metadata.get('drivers', []))} drivers[/green]"
        )
        return len(result.driver_hashes)

    async def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a single driver file."""
        if not self._db:
            raise RuntimeError("Analyzer not initialized")

        console.print(f"[cyan]Analyzing:[/cyan] {file_path.name}")

        # PE analysis
        pe_result = analyze_pe(file_path)

        if pe_result.errors:
            for error in pe_result.errors:
                console.print(f"[yellow]Warning:[/yellow] {error}")

        # Check against LOLDrivers
        in_loldrivers = False
        if self.config.check_loldrivers:
            sha256 = pe_result.driver.hashes.sha256.lower()
            in_loldrivers = sha256 in self._loldrivers_hashes or await self._db.is_in_loldrivers(
                sha256
            )

        # Check VirusTotal
        vt_detections = None
        vt_total = None
        if self.config.check_virustotal and self._virustotal:
            try:
                vt_result = await self._virustotal.lookup_hash(pe_result.driver.hashes.sha256)
                if vt_result:
                    vt_detections = vt_result.get("detections", 0)
                    vt_total = vt_result.get("total_engines", 0)
            except Exception as e:
                console.print(f"[yellow]VT lookup failed:[/yellow] {e}")

        # Calculate risk score
        risk_score = calculate_risk_score(pe_result, in_loldrivers)

        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO

        # Build notes
        notes: list[str] = []
        if pe_result.dangerous_imports:
            notes.append(f"Dangerous imports: {', '.join(pe_result.dangerous_imports)}")
        if pe_result.suspicious_strings:
            notes.append(f"Suspicious patterns: {', '.join(pe_result.suspicious_strings)}")

        # Create analysis result
        analysis_result = AnalysisResult(
            driver=pe_result.driver,
            vulnerabilities=pe_result.potential_vulns,
            risk_level=risk_level,
            risk_score=risk_score,
            in_loldrivers=in_loldrivers,
            in_ms_blocklist=False,  # TODO: Check MS blocklist
            vt_detections=vt_detections,
            vt_total=vt_total,
            notes=notes,
            dangerous_imports=pe_result.dangerous_imports,
        )

        # Persist
        if self.config.save_to_db:
            await self._db.save_analysis_result(analysis_result)

        # Generate YAML if requested
        if self.config.generate_yaml and self.config.yaml_output_dir:
            yaml_content = generate_loldrivers_yaml(analysis_result)
            yaml_filename = generate_loldrivers_filename(analysis_result)
            yaml_path = self.config.yaml_output_dir / yaml_filename
            yaml_path.write_text(yaml_content)
            console.print(f"[green]Generated:[/green] {yaml_path}")

        return analysis_result

    async def analyze_directory(
        self,
        dir_path: Path,
        recursive: bool = False,
    ) -> list[AnalysisResult]:
        """Analyze all drivers in a directory."""
        pattern = "**/*.sys" if recursive else "*.sys"
        driver_files = list(dir_path.glob(pattern))

        if not driver_files:
            console.print("[yellow]No .sys files found[/yellow]")
            return []

        console.print(f"[cyan]Found {len(driver_files)} driver(s)[/cyan]")

        results: list[AnalysisResult] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(driver_files))

            for file_path in driver_files:
                try:
                    result = await self.analyze_file(file_path)
                    results.append(result)
                except Exception as e:
                    console.print(f"[red]Error analyzing {file_path}:[/red] {e}")
                finally:
                    progress.advance(task)

        return results

    async def search_nvd(
        self,
        query: str,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Search NVD for driver-related CVEs."""
        if not self._nvd:
            raise RuntimeError("Analyzer not initialized")

        console.print(f"[cyan]Searching NVD for:[/cyan] {query}")

        result = await self._nvd.fetch(
            keyword=query,
            start_date=since,
        )

        if result.has_errors:
            for error in result.errors:
                console.print(f"[yellow]Warning:[/yellow] {error}")

        cve_entries: list[dict[str, Any]] = result.metadata.get("cve_entries", [])[:limit]
        console.print(f"[green]Found {len(cve_entries)} CVE(s)[/green]")

        return cve_entries

    async def get_stats(self) -> dict[str, int]:
        """Get database statistics."""
        if not self._db:
            raise RuntimeError("Analyzer not initialized")
        return await self._db.get_stats()


async def run_analyzer(config: AnalyzerConfig | None = None) -> Analyzer:
    """Create and initialize an analyzer instance."""
    analyzer = Analyzer(config=config or AnalyzerConfig())
    await analyzer.initialize()
    return analyzer
