"""CLI interface for driver-search."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from driver_search import __version__
from driver_search.config import get_settings

app = typer.Typer(
    name="driver-search",
    help="Vulnerable driver research tooling for blocklist contribution.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"driver-search v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-v", callback=version_callback, is_eager=True),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", "-d", help="Enable debug output"),
    ] = False,
) -> None:
    """Driver Search - Vulnerable driver research tooling."""
    if debug:
        settings = get_settings()
        settings.debug = True


@app.command()
def analyze(
    path: Annotated[
        Path,
        typer.Argument(help="Path to driver file or directory"),
    ],
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Recursively scan directories"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file for results"),
    ] = None,
) -> None:
    """Analyze driver(s) for vulnerabilities."""
    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(1)

    if path.is_file():
        console.print(f"Analyzing: {path}")
        # TODO: Implement single file analysis
        console.print("[yellow]Analysis not yet implemented[/yellow]")
    else:
        pattern = "**/*.sys" if recursive else "*.sys"
        drivers = list(path.glob(pattern))
        console.print(f"Found {len(drivers)} driver(s) to analyze")
        # TODO: Implement batch analysis


@app.command()
def search_nvd(
    query: Annotated[
        str,
        typer.Argument(help="Search query for NVD"),
    ],
    since: Annotated[
        str | None,
        typer.Option("--since", "-s", help="Only show CVEs since date (YYYY-MM-DD)"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum results to return"),
    ] = 50,
) -> None:
    """Search NVD for driver-related CVEs."""
    console.print(f"Searching NVD for: {query}")
    # TODO: Implement NVD search
    console.print("[yellow]NVD search not yet implemented[/yellow]")


@app.command()
def monitor(
    sources: Annotated[
        str,
        typer.Option(
            "--sources",
            "-s",
            help="Comma-separated list of sources (nvd,loldrivers,vendors,wucatalog)",
        ),
    ] = "nvd,loldrivers",
    interval: Annotated[
        int,
        typer.Option("--interval", "-i", help="Poll interval in hours"),
    ] = 6,
    once: Annotated[
        bool,
        typer.Option("--once", help="Run once instead of continuously"),
    ] = False,
) -> None:
    """Monitor sources for new vulnerable drivers."""
    source_list = [s.strip() for s in sources.split(",")]
    console.print(f"Monitoring sources: {', '.join(source_list)}")
    console.print(f"Poll interval: {interval} hours")
    # TODO: Implement monitoring loop
    console.print("[yellow]Monitoring not yet implemented[/yellow]")


@app.command()
def sync_loldrivers(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path for synced data"),
    ] = None,
) -> None:
    """Sync LOLDrivers database."""
    console.print("Syncing LOLDrivers database...")
    # TODO: Implement LOLDrivers sync
    console.print("[yellow]LOLDrivers sync not yet implemented[/yellow]")


@app.command()
def export(
    format: Annotated[
        str,
        typer.Argument(help="Export format (loldrivers, msrc, json)"),
    ],
    hash: Annotated[
        str | None,
        typer.Option("--hash", "-h", help="Driver hash to export"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file"),
    ] = None,
) -> None:
    """Export analysis results in various formats."""
    console.print(f"Exporting in {format} format")
    # TODO: Implement export
    console.print("[yellow]Export not yet implemented[/yellow]")


@app.command()
def dashboard() -> None:
    """Show dashboard of findings."""
    settings = get_settings()

    table = Table(title="Driver Search Dashboard")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    # TODO: Get actual stats from database
    table.add_row("Drivers analyzed", "0")
    table.add_row("Vulnerabilities found", "0")
    table.add_row("In LOLDrivers", "0")
    table.add_row("Not in blocklist", "0")
    table.add_row("High risk", "0")

    console.print(table)
    console.print(f"\nDatabase: {settings.output.db_path}")
    console.print(f"Cache: {settings.output.cache_dir}")


if __name__ == "__main__":
    app()
