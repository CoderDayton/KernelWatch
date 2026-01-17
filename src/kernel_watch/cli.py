"""CLI interface for kernel-watch."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kernel_watch import __version__
from kernel_watch.config import get_settings

app = typer.Typer(
    name="kernel-watch",
    help="Vulnerable driver research tooling for blocklist contribution.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"kernel-watch v{__version__}")
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
    """KernelWatch - Vulnerable driver research tooling."""
    if debug:
        settings = get_settings()
        settings.debug = True


def _run_async(coro: Any) -> Any:
    """Run async function in sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _format_risk_level(level: str, score: int) -> str:
    """Format risk level with color."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = colors.get(level, "white")
    return f"[{color}]{level.upper()}[/{color}] ({score})"


def _print_analysis_result(result: Any) -> None:
    """Pretty print an analysis result."""
    driver = result.driver

    # Header
    console.print(
        Panel(
            f"[bold]{driver.name}[/bold]\nSHA256: [dim]{driver.hashes.sha256}[/dim]",
            title="Driver Analysis",
            border_style="cyan",
        )
    )

    # Info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Field", style="cyan")
    info_table.add_column("Value")

    if driver.vendor:
        info_table.add_row("Vendor", driver.vendor)
    if driver.version:
        info_table.add_row("Version", driver.version)
    if driver.description:
        info_table.add_row("Description", driver.description[:80])
    if driver.signature:
        info_table.add_row("Signer", driver.signature.signer[:60])
    if driver.compile_time:
        info_table.add_row("Compiled", driver.compile_time.strftime("%Y-%m-%d"))

    console.print(info_table)
    console.print()

    # Risk assessment
    console.print(f"Risk: {_format_risk_level(result.risk_level.value, result.risk_score)}")

    if result.in_loldrivers:
        console.print("[yellow]⚠ Already in LOLDrivers[/yellow]")
    else:
        console.print("[green]✓ Not in LOLDrivers (potential new finding)[/green]")

    if result.detection_ratio:
        console.print(f"VirusTotal: {result.detection_ratio}")

    # Dangerous imports
    if result.dangerous_imports:
        console.print("\n[bold red]Dangerous Imports:[/bold red]")
        for imp in result.dangerous_imports:
            console.print(f"  • {imp}")

    # Vulnerabilities
    if result.vulnerabilities:
        console.print("\n[bold red]Potential Vulnerabilities:[/bold red]")
        for vuln in result.vulnerabilities:
            confidence = f"[dim]({vuln.confidence:.0%})[/dim]"
            console.print(f"  • {vuln.vuln_type.value}: {vuln.description} {confidence}")

    console.print()


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
        typer.Option("--output", "-o", help="Output directory for YAML files"),
    ] = None,
    no_vt: Annotated[
        bool,
        typer.Option("--no-vt", help="Skip VirusTotal lookup"),
    ] = False,
    yaml: Annotated[
        bool,
        typer.Option("--yaml", "-y", help="Generate LOLDrivers YAML output"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON"),
    ] = False,
) -> None:
    """Analyze driver(s) for vulnerabilities."""
    from kernel_watch.analyzer import AnalyzerConfig, run_analyzer

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(1)

    config = AnalyzerConfig(
        check_virustotal=not no_vt,
        generate_yaml=yaml,
        yaml_output_dir=output or Path("data/reports"),
    )

    async def _analyze() -> None:
        analyzer = await run_analyzer(config)
        try:
            # Sync LOLDrivers first for accurate "new finding" detection
            await analyzer.sync_loldrivers()

            if path.is_file():
                result = await analyzer.analyze_file(path)

                if json_output:
                    from kernel_watch.output.json import analysis_result_to_dict, to_json

                    print(to_json(analysis_result_to_dict(result)))
                else:
                    _print_analysis_result(result)

                    # Summary
                    if result.risk_score >= 50 and not result.in_loldrivers:
                        console.print(
                            "[bold green]→ High-value finding! "
                            "Consider submitting to LOLDrivers.[/bold green]"
                        )
            else:
                results = await analyzer.analyze_directory(path, recursive)

                if json_output:
                    from kernel_watch.output.json import analysis_result_to_dict, to_json

                    print(to_json([analysis_result_to_dict(r) for r in results]))
                # Summary table
                elif results:
                    console.print("\n[bold]Summary[/bold]")
                    summary_table = Table()
                    summary_table.add_column("Driver")
                    summary_table.add_column("Risk")
                    summary_table.add_column("In Blocklist")
                    summary_table.add_column("Dangerous Imports")

                    for r in sorted(results, key=lambda x: x.risk_score, reverse=True):
                        blocklist = "Yes" if r.in_loldrivers else "[green]No[/green]"
                        imports = ", ".join(r.dangerous_imports[:3])
                        if len(r.dangerous_imports) > 3:
                            imports += f" +{len(r.dangerous_imports) - 3}"

                        summary_table.add_row(
                            r.driver.name[:30],
                            _format_risk_level(r.risk_level.value, r.risk_score),
                            blocklist,
                            imports or "-",
                        )

                    console.print(summary_table)

                    # Highlight new findings
                    new_findings = [
                        r for r in results if not r.in_loldrivers and r.risk_score >= 50
                    ]
                    if new_findings:
                        console.print(
                            f"\n[bold green]Found {len(new_findings)} potential new "
                            f"vulnerable driver(s) not in blocklists![/bold green]"
                        )
        finally:
            await analyzer.close()

    _run_async(_analyze())


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
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON"),
    ] = False,
) -> None:
    """Search NVD for driver-related CVEs."""
    from kernel_watch.analyzer import run_analyzer

    since_dt = None
    if since:
        try:
            since_dt = datetime.strptime(since, "%Y-%m-%d")
        except ValueError as err:
            console.print("[red]Error:[/red] Invalid date format. Use YYYY-MM-DD")
            raise typer.Exit(1) from err

    async def _search() -> None:
        analyzer = await run_analyzer()
        try:
            cves = await analyzer.search_nvd(query, since=since_dt, limit=limit)

            if not cves:
                if json_output:
                    print("[]")
                else:
                    console.print("[yellow]No CVEs found[/yellow]")
                return

            if json_output:
                from kernel_watch.output.json import cve_entries_to_list, to_json

                print(to_json(cve_entries_to_list(cves)))
            else:
                table = Table(title=f"NVD Results for '{query}'")
                table.add_column("CVE ID", style="cyan")
                table.add_column("CVSS", justify="right")
                table.add_column("Published")
                table.add_column("Description", max_width=60)

                for cve in cves:
                    cvss = cve.get("cvss_score")
                    cvss_str = f"{cvss:.1f}" if cvss else "-"
                    if cvss and cvss >= 7.0:
                        cvss_str = f"[red]{cvss_str}[/red]"
                    elif cvss and cvss >= 4.0:
                        cvss_str = f"[yellow]{cvss_str}[/yellow]"

                    desc = cve.get("description", "")[:100]
                    if len(cve.get("description", "")) > 100:
                        desc += "..."

                    table.add_row(
                        cve.get("cve_id", ""),
                        cvss_str,
                        cve.get("published", "")[:10],
                        desc,
                    )

                console.print(table)

                # Highlight driver-related CVEs
                driver_keywords = ["driver", "kernel", "privilege", "escalation", "ring0"]
                driver_cves = [
                    c
                    for c in cves
                    if any(kw in c.get("description", "").lower() for kw in driver_keywords)
                ]
                if driver_cves:
                    msg = (
                        f"\n[bold cyan]{len(driver_cves)} CVE(s) "
                        "mention driver/kernel keywords[/bold cyan]"
                    )
                    console.print(msg)
        finally:
            await analyzer.close()

    _run_async(_search())


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
    from kernel_watch.monitor import run_monitor

    source_list = [s.strip() for s in sources.split(",")]
    console.print(f"[cyan]Monitoring sources:[/cyan] {', '.join(source_list)}")

    if not once:
        console.print(f"[cyan]Poll interval:[/cyan] {interval} hours")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    _run_async(run_monitor(source_list, interval_hours=interval, once=once))


@app.command()
def sync_loldrivers(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path for synced data"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON"),
    ] = False,
) -> None:
    """Sync LOLDrivers database."""
    from kernel_watch.analyzer import run_analyzer

    async def _sync() -> None:
        analyzer = await run_analyzer()
        try:
            count = await analyzer.sync_loldrivers()

            if json_output:
                print(f'{{"count": {count}}}')
            else:
                console.print(f"[green]Successfully synced {count} driver hashes[/green]")

            if output:
                # Export to file
                stats = await analyzer.get_stats()
                output.write_text(f"LOLDrivers hashes: {stats.get('loldrivers_hashes', 0)}\n")
                if not json_output:
                    console.print(f"[green]Stats written to {output}[/green]")
        finally:
            await analyzer.close()

    _run_async(_sync())


@app.command()
def export(
    format: Annotated[
        str,
        typer.Argument(help="Export format (loldrivers, msrc, json)"),
    ],
    hash: Annotated[
        str | None,
        typer.Option("--hash", help="Driver hash to export"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file"),
    ] = None,
) -> None:
    """Export analysis results in various formats."""
    from kernel_watch.db import get_database
    from kernel_watch.output.loldrivers import generate_loldrivers_yaml

    if format not in ("loldrivers", "msrc", "json", "yara"):
        console.print(f"[red]Error:[/red] Unknown format '{format}'")
        console.print("Supported formats: loldrivers, msrc, json, yara")
        raise typer.Exit(1)

    async def _export() -> None:
        async with get_database() as db:
            if hash:
                driver = await db.get_driver(hash)
                if not driver:
                    console.print(f"[red]Error:[/red] Driver not found: {hash}")
                    raise typer.Exit(1)

                # Create minimal analysis result for export
                # (TODO: Fetch full result from DB if available)
                from kernel_watch.models import AnalysisResult, RiskLevel

                result = AnalysisResult(
                    driver=driver,
                    risk_level=RiskLevel.MEDIUM,
                    risk_score=50,
                )

                if format == "loldrivers":
                    yaml_content = generate_loldrivers_yaml(result)
                    if output:
                        output.write_text(yaml_content)
                        console.print(f"[green]Written to {output}[/green]")
                    else:
                        console.print(yaml_content)
                elif format == "yara":
                    from kernel_watch.output.yara import generate_yara_rule

                    rule = generate_yara_rule(result)
                    if output:
                        output.write_text(rule)
                        console.print(f"[green]Written to {output}[/green]")
                    else:
                        console.print(rule)
                elif format == "json":
                    from kernel_watch.output.json import analysis_result_to_dict, to_json

                    json_str = to_json(analysis_result_to_dict(result), pretty=True)
                    if output:
                        output.write_text(json_str)
                        console.print(f"[green]Written to {output}[/green]")
                    else:
                        console.print(json_str)
                else:
                    console.print(f"[yellow]{format} export not yet implemented[/yellow]")
            else:
                console.print("[red]Error:[/red] --hash is required")
                raise typer.Exit(1)

    _run_async(_export())


@app.command()
def dashboard(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON"),
    ] = False,
) -> None:
    """Show dashboard of findings."""
    from kernel_watch.db import get_database

    settings = get_settings()

    async def _dashboard() -> None:
        try:
            async with get_database() as db:
                stats = await db.get_stats()

                if json_output:
                    from kernel_watch.output.json import stats_to_dict, to_json

                    print(to_json(stats_to_dict(stats)))
                else:
                    table = Table(title="KernelWatch Dashboard")
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", style="green", justify="right")

                    table.add_row("Drivers analyzed", str(stats.get("drivers", 0)))
                    table.add_row("Analysis runs", str(stats.get("analyses", 0)))
                    table.add_row("Vulnerabilities found", str(stats.get("vulnerabilities", 0)))
                    table.add_row("LOLDrivers hashes", str(stats.get("loldrivers_hashes", 0)))
                    table.add_row("Critical risk", str(stats.get("critical_risk", 0)))

                    console.print(table)
                    console.print(f"\n[dim]Database:[/dim] {settings.output.db_path}")
                    console.print(f"[dim]Cache:[/dim] {settings.output.cache_dir}")
        except Exception as e:
            if json_output:
                print(f'{{"error": "{e!s}"}}')
            else:
                console.print(f"[yellow]Database not initialized:[/yellow] {e}")
                console.print("Run 'kernel-watch sync-loldrivers' to initialize.")

    _run_async(_dashboard())


if __name__ == "__main__":
    app()
