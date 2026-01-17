"""Async monitoring daemon for continuous source polling."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from rich.console import Console
from rich.live import Live
from rich.table import Table

from kernel_watch.config import get_settings
from kernel_watch.db import Database
from kernel_watch.sources.loldrivers import LOLDriversSource
from kernel_watch.sources.nvd import NVDSource

if TYPE_CHECKING:
    from kernel_watch.sources.base import Source, SourceResult

console = Console()


@dataclass
class MonitorState:
    """Tracks monitoring state across poll cycles."""

    last_poll: dict[str, datetime] = field(default_factory=dict)
    total_findings: dict[str, int] = field(default_factory=dict)
    errors: dict[str, list[str]] = field(default_factory=dict)
    new_hashes: set[str] = field(default_factory=set)
    new_cves: set[str] = field(default_factory=set)


class Monitor:
    """Continuous monitoring daemon for driver research sources."""

    def __init__(
        self,
        sources: list[str],
        interval_hours: int = 6,
    ) -> None:
        self._source_names = sources
        self._interval = timedelta(hours=interval_hours)
        self._sources: dict[str, Source] = {}
        self._db: Database | None = None
        self._state = MonitorState()
        self._running = False
        self._known_hashes: set[str] = set()

    async def initialize(self) -> None:
        """Initialize sources and database."""
        settings = get_settings()
        settings.ensure_directories()

        # Database
        self._db = Database()
        await self._db.connect()

        # Load known hashes from LOLDrivers table
        # This lets us detect truly new additions

        # Initialize requested sources
        for name in self._source_names:
            source = await self._create_source(name)
            if source:
                self._sources[name] = source
                self._state.last_poll[name] = datetime.min
                self._state.total_findings[name] = 0
                self._state.errors[name] = []

        if not self._sources:
            raise RuntimeError("No valid sources configured")

        console.print(f"[green]Initialized {len(self._sources)} source(s)[/green]")

    async def _create_source(self, name: str) -> Source | None:  # noqa: PLR0911
        """Create a source by name."""
        settings = get_settings()

        if name == "nvd":
            api_key = None
            if settings.api_keys.nvd_api_key:
                api_key = settings.api_keys.nvd_api_key.get_secret_value()
            return NVDSource(api_key=api_key, keywords=settings.monitoring.nvd_keywords)

        if name == "loldrivers":
            token = None
            if settings.api_keys.github_token:
                token = settings.api_keys.github_token.get_secret_value()
            return LOLDriversSource(github_token=token)

        if name == "virustotal":
            if settings.api_keys.virustotal_api_key:
                from kernel_watch.sources.virustotal import VirusTotalSource

                api_key = settings.api_keys.virustotal_api_key.get_secret_value()
                return VirusTotalSource(api_key=api_key)
            console.print("[yellow]VirusTotal requires API key, skipping[/yellow]")
            return None

        if name == "wucatalog":
            console.print("[yellow]Windows Update Catalog not yet implemented[/yellow]")
            return None

        if name == "vendors":
            console.print("[yellow]Vendor scrapers not yet implemented[/yellow]")
            return None

        console.print(f"[yellow]Unknown source: {name}[/yellow]")
        return None

    async def close(self) -> None:
        """Clean up resources."""
        self._running = False
        for source in self._sources.values():
            if hasattr(source, "close"):
                await source.close()
        if self._db:
            await self._db.close()

    async def poll_once(self) -> dict[str, SourceResult]:
        """Poll all sources once and return results."""
        results: dict[str, SourceResult] = {}

        for name, source in self._sources.items():
            console.print(f"[cyan]Polling {name}...[/cyan]")

            try:
                since = self._state.last_poll.get(name)
                if since == datetime.min:
                    since = datetime.now() - timedelta(days=30)

                # Collect incremental results
                source_results: list[SourceResult] = []
                async for result in source.fetch_incremental(since=since):
                    source_results.append(result)

                # Merge results
                merged = self._merge_results(source_results, name)
                results[name] = merged

                # Update state
                self._state.last_poll[name] = datetime.now()
                self._state.total_findings[name] += merged.total_items

                # Track new findings
                for h in merged.driver_hashes:
                    if h.lower() not in self._known_hashes:
                        self._state.new_hashes.add(h.lower())
                        self._known_hashes.add(h.lower())

                for cve in merged.cve_ids:
                    self._state.new_cves.add(cve)

                # Log findings
                if merged.total_items > 0:
                    console.print(
                        f"[green]{name}:[/green] {len(merged.driver_hashes)} hashes, "
                        f"{len(merged.cve_ids)} CVEs"
                    )

                if merged.errors:
                    self._state.errors[name].extend(merged.errors)
                    for err in merged.errors:
                        console.print(f"[yellow]{name} warning:[/yellow] {err}")

            except Exception as e:
                console.print(f"[red]{name} error:[/red] {e}")
                self._state.errors[name].append(str(e))

        return results

    def _merge_results(
        self,
        results: list[SourceResult],
        source_name: str,
    ) -> SourceResult:
        """Merge multiple source results into one."""
        from kernel_watch.sources.base import SourceResult

        merged = SourceResult(source_name=source_name)

        for r in results:
            merged.driver_hashes.extend(r.driver_hashes)
            merged.cve_ids.extend(r.cve_ids)
            merged.download_urls.extend(r.download_urls)
            merged.errors.extend(r.errors)
            for k, v in r.metadata.items():
                if k not in merged.metadata:
                    merged.metadata[k] = v
                elif isinstance(v, list):
                    merged.metadata[k].extend(v)

        # Deduplicate
        merged.driver_hashes = list(dict.fromkeys(merged.driver_hashes))
        merged.cve_ids = list(dict.fromkeys(merged.cve_ids))
        merged.download_urls = list(dict.fromkeys(merged.download_urls))

        return merged

    def _render_status_table(self) -> Table:
        """Render current monitoring status as a table."""
        table = Table(title="Monitor Status", show_edge=False)
        table.add_column("Source", style="cyan")
        table.add_column("Last Poll", style="dim")
        table.add_column("Findings", justify="right")
        table.add_column("Errors", justify="right")

        for name in self._sources:
            last_poll = self._state.last_poll.get(name, datetime.min)
            poll_str = "never" if last_poll == datetime.min else last_poll.strftime("%H:%M:%S")

            findings = self._state.total_findings.get(name, 0)
            errors = len(self._state.errors.get(name, []))

            error_str = str(errors) if errors == 0 else f"[red]{errors}[/red]"

            table.add_row(name, poll_str, str(findings), error_str)

        return table

    async def run(self, once: bool = False) -> None:
        """Run the monitoring loop."""
        self._running = True

        # Initial poll
        await self.poll_once()

        if once:
            self._print_summary()
            return

        # Continuous monitoring
        console.print(f"\n[dim]Next poll in {self._interval}[/dim]\n")

        while self._running:
            try:
                # Show status while waiting
                with Live(self._render_status_table(), console=console, refresh_per_second=0.5):
                    await asyncio.sleep(self._interval.total_seconds())

                if not self._running:
                    break

                # Poll again
                console.print(f"\n[cyan]Polling at {datetime.now().strftime('%H:%M:%S')}[/cyan]")
                await self.poll_once()

            except asyncio.CancelledError:
                break
            except KeyboardInterrupt:
                break

        self._print_summary()

    def _print_summary(self) -> None:
        """Print final summary."""
        console.print("\n[bold]Monitoring Summary[/bold]")
        console.print(self._render_status_table())

        if self._state.new_hashes:
            console.print(
                f"\n[green]New driver hashes discovered: {len(self._state.new_hashes)}[/green]"
            )
        if self._state.new_cves:
            console.print(f"[green]New CVEs found: {len(self._state.new_cves)}[/green]")


async def run_monitor(
    sources: list[str],
    interval_hours: int = 6,
    once: bool = False,
) -> None:
    """Run the monitoring daemon."""
    monitor = Monitor(sources, interval_hours)
    await monitor.initialize()

    try:
        await monitor.run(once=once)
    finally:
        await monitor.close()
