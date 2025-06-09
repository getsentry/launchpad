"""Command-line interface for app size analyzer."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .analyzers.ios import IOSAnalyzer
from .models import AnalysisResults
from .utils.logging import setup_logging


console = Console()


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version information and exit.")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """App Size Analyzer - Analyze iOS and Android app bundle sizes."""
    if version:
        click.echo(f"App Size Analyzer v{__version__}")
        ctx.exit()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="INPUT_PATH")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default="ios-analysis-report.json",
    help="Output path for the JSON analysis report.",
    show_default=True,
)
@click.option(
    "--working-dir",
    type=click.Path(path_type=Path),
    help="Working directory for temporary files (default: system temp).",
)
@click.option(
    "--skip-swift-metadata", is_flag=True, help="Skip Swift metadata parsing for faster analysis."
)
@click.option("--skip-symbols", is_flag=True, help="Skip symbol extraction and analysis.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except errors.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "table"], case_sensitive=False),
    default="json",
    help="Output format for results.",
    show_default=True,
)
def ios(
    input_path: Path,
    output: Path,
    working_dir: Optional[Path],
    skip_swift_metadata: bool,
    skip_symbols: bool,
    verbose: bool,
    quiet: bool,
    output_format: str,
) -> None:
    """Analyze an iOS app bundle and generate a size report.

    INPUT_PATH can be:
    - .xcarchive.zip file
    """
    setup_logging(verbose=verbose, quiet=quiet)

    if verbose and quiet:
        raise click.UsageError("Cannot specify both --verbose and --quiet")

    _validate_ios_input(input_path)

    if not quiet:
        console.print(f"[bold blue]App Size Analyzer v{__version__}[/bold blue]")
        console.print(f"Analyzing iOS app: [cyan]{input_path}[/cyan]")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print()

    try:
        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet,
        ) as progress:
            task = progress.add_task("Analyzing iOS app bundle...", total=None)

            analyzer = IOSAnalyzer(
                working_dir=working_dir,
                skip_swift_metadata=skip_swift_metadata,
                skip_symbols=skip_symbols,
            )
            results = analyzer.analyze(input_path)

            progress.update(task, description="Analysis complete!")

        end_time = time.time()
        duration = end_time - start_time

        results = results.model_copy(update={"analysis_duration": duration})

        if output_format == "json":
            _write_json_output(results, output, quiet)
        else:
            _print_table_output(results, quiet)

        if not quiet:
            console.print(f"\n[bold green]✓[/bold green] Analysis completed in {duration:.2f}s")
            _print_summary(results)

    except Exception as e:
        if verbose:
            console.print_exception()
        else:
            console.print(f"[bold red]Error:[/bold red] {e}")
        raise click.Abort()


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="INPUT_PATH")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default="android-analysis-report.json",
    help="Output path for the JSON analysis report.",
    show_default=True,
)
def android(input_path: Path, output: Path) -> None:
    """Analyze an Android app bundle and generate a size report.

    INPUT_PATH can be:
    - Android .apk file
    - Android .aab file

    [Coming Soon - Android analysis is not yet implemented]
    """
    console.print("[bold red]Android analysis is not yet implemented.[/bold red]")
    console.print("This feature is coming soon!")
    raise click.Abort()


def _validate_ios_input(input_path: Path) -> None:
    """Validate that the input path looks like an iOS artifact."""
    suffix = input_path.suffix.lower()
    valid_extensions = {".zip"}

    if suffix not in valid_extensions:
        raise click.BadParameter(
            f"'{input_path}' doesn't look like a typical iOS artifact. "
            f"Expected one of: {', '.join(sorted(valid_extensions))}"
        )


def _write_json_output(results: AnalysisResults, output_path: Path, quiet: bool) -> None:
    """Write results to JSON file."""
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON with proper formatting
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results.to_dict(), f, indent=2, ensure_ascii=False)

    if not quiet:
        console.print(f"[bold green]✓[/bold green] Results written to: [cyan]{output_path}[/cyan]")


def _print_table_output(results: AnalysisResults, quiet: bool) -> None:
    """Print results in table format to console."""
    if quiet:
        return

    # App Info Table
    app_table = Table(title="App Information", show_header=True, header_style="bold magenta")
    app_table.add_column("Property", style="cyan")
    app_table.add_column("Value", style="white")

    app_info = results.app_info
    app_table.add_row("Name", app_info.name)
    app_table.add_row("Bundle ID", app_info.bundle_id)
    app_table.add_row("Version", f"{app_info.version} ({app_info.build})")
    app_table.add_row("Min OS", app_info.minimum_os_version)
    app_table.add_row("Platforms", ", ".join(app_info.supported_platforms))

    console.print(app_table)
    console.print()

    # File Analysis Table
    file_table = Table(title="File Analysis", show_header=True, header_style="bold green")
    file_table.add_column("Metric", style="cyan")
    file_table.add_column("Value", style="white")

    file_analysis = results.file_analysis
    file_table.add_row("Total Size", _format_bytes(file_analysis.total_size))
    file_table.add_row("File Count", str(file_analysis.file_count))
    file_table.add_row("Duplicate Files", str(len(file_analysis.duplicate_files)))
    file_table.add_row("Potential Savings", _format_bytes(file_analysis.total_duplicate_savings))

    console.print(file_table)
    console.print()

    # File Types Table
    if file_analysis.file_type_sizes:
        type_table = Table(title="File Types", show_header=True, header_style="bold yellow")
        type_table.add_column("Type", style="cyan")
        type_table.add_column("Size", style="white")
        type_table.add_column("Percentage", style="green")

        total_size = file_analysis.total_size
        for file_type, size in sorted(
            file_analysis.file_type_sizes.items(), key=lambda x: x[1], reverse=True
        )[
            :10
        ]:  # Top 10 file types
            percentage = (size / total_size) * 100 if total_size > 0 else 0
            type_table.add_row(file_type or "unknown", _format_bytes(size), f"{percentage:.1f}%")

        console.print(type_table)


def _print_summary(results: AnalysisResults) -> None:
    """Print a brief summary of the analysis."""
    file_analysis = results.file_analysis
    binary_analysis = results.binary_analysis

    console.print("\n[bold]Summary:[/bold]")
    console.print(f"• Total app size: [cyan]{_format_bytes(file_analysis.total_size)}[/cyan]")
    console.print(
        f"• Executable size: [cyan]{_format_bytes(binary_analysis.executable_size)}[/cyan]"
    )
    console.print(f"• File count: [cyan]{file_analysis.file_count:,}[/cyan]")
    console.print(f"• Architectures: [cyan]{', '.join(binary_analysis.architectures)}[/cyan]")

    if file_analysis.duplicate_files:
        console.print(
            f"• Potential savings from duplicates: "
            f"[yellow]{_format_bytes(file_analysis.total_duplicate_savings)}[/yellow]"
        )


def _format_bytes(size: int) -> str:
    """Format byte size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
