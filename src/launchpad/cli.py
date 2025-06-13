"""Command-line interface for launchpad."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .analyzers.android import AndroidAnalyzer
from .analyzers.ios import IOSAnalyzer
from .artifacts.android.apk import APK
from .models import AndroidAnalysisResults, IOSAnalysisResults
from .service import run_service
from .utils.logging import setup_logging

console = Console()


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version information and exit.")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """Launchpad - Analyze iOS and Android app bundle sizes."""
    if version:
        click.echo(f"Launchpad v{__version__}")
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
@click.option("--skip-swift-metadata", is_flag=True, help="Skip Swift metadata parsing for faster analysis.")
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
    working_dir: Path | None,
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
            _print_ios_table_output(results, quiet)

        if not quiet:
            console.print(f"\n[bold green]✓[/bold green] Analysis completed in {duration:.2f}s")
            _print_ios_summary(results)

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
def android(
    input_path: Path,
    output: Path,
    verbose: bool,
    quiet: bool,
    output_format: str,
) -> None:
    """Analyze an Android app bundle and generate a size report.

    INPUT_PATH can be:
    - Android .apk file
    - Android .aab file (coming soon)
    """
    setup_logging(verbose=verbose, quiet=quiet)

    if verbose and quiet:
        raise click.UsageError("Cannot specify both --verbose and --quiet")

    if not quiet:
        console.print(f"[bold blue]App Size Analyzer v{__version__}[/bold blue]")
        console.print(f"Analyzing Android app: [cyan]{input_path}[/cyan]")
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
            task = progress.add_task("Analyzing Android app bundle...", total=None)

            # Read APK file
            with open(input_path, "rb") as f:
                apk = APK(f.read())

            analyzer = AndroidAnalyzer(apk)
            results = analyzer.analyze()

            progress.update(task, description="Analysis complete!")

        end_time = time.time()
        duration = end_time - start_time

        results = results.model_copy(update={"analysis_duration": duration})

        if output_format == "json":
            _write_json_output(results, output, quiet)
        else:
            _print_android_table_output(results, quiet)

    except Exception as e:
        if verbose:
            console.print_exception()
        else:
            console.print(f"[bold red]Error:[/bold red] {e}")
        raise click.Abort()


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind the server to.", show_default=True)
@click.option("--port", default=2218, help="Port to bind the server to.", show_default=True)
@click.option("--dev", "mode", flag_value="development", help="Run in development mode (default).")
@click.option("--prod", "mode", flag_value="production", help="Run in production mode.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
def serve(host: str, port: int, mode: str | None, verbose: bool) -> None:
    """Start the Launchpad server.

    Runs the HTTP server with health check endpoints and Kafka consumer
    for processing analysis requests.

    By default, runs in development mode with debug logging and features enabled.
    Use --prod for production mode with optimized settings.
    """
    # Default to development mode if no mode specified
    if mode is None:
        mode = "development"

    # If verbose wasn't explicitly set and we're in development mode, enable verbose
    if not verbose and mode == "development":
        verbose = True

    # Set environment variables for configuration
    os.environ["LAUNCHPAD_ENV"] = mode
    os.environ["LAUNCHPAD_HOST"] = host
    os.environ["LAUNCHPAD_PORT"] = str(port)

    setup_logging(verbose=verbose, quiet=False)

    if not verbose:
        # Reduce noise from some libraries
        logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    mode_display = "Development" if mode == "development" else "Production"
    console.print(f"[bold blue]Launchpad {mode_display} Server v{__version__}[/bold blue]")
    console.print(f"Starting server on [cyan]http://{host}:{port}[/cyan]")

    mode_color = "green" if mode == "development" else "yellow"
    console.print(f"Mode: [{mode_color}]{mode}[/{mode_color}]")
    console.print("Press Ctrl+C to stop the server")
    console.print()

    try:
        asyncio.run(run_service())
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Server error:[/bold red] {e}")
        if verbose:
            console.print_exception()
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


def _write_json_output(results: IOSAnalysisResults | AndroidAnalysisResults, output_path: Path, quiet: bool) -> None:
    """Write results to JSON file."""
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON with proper formatting
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results.to_dict(), f, indent=2, ensure_ascii=False)

    if not quiet:
        console.print(f"[bold green]✓[/bold green] Results written to: [cyan]{output_path}[/cyan]")


def _print_ios_table_output(results: IOSAnalysisResults, quiet: bool) -> None:
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
    if results.file_analysis:
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
        for file_type, size in sorted(file_analysis.file_type_sizes.items(), key=lambda x: x[1], reverse=True)[
            :10
        ]:  # Top 10 file types
            percentage = (size / total_size) * 100 if total_size > 0 else 0
            type_table.add_row(file_type or "unknown", _format_bytes(size), f"{percentage:.1f}%")

        console.print(type_table)


def _print_android_table_output(results: AndroidAnalysisResults, quiet: bool) -> None:
    """Print results in table format to console."""
    if quiet:
        return

    # App Info Table
    app_table = Table(title="App Information", show_header=True, header_style="bold magenta")
    app_table.add_column("Property", style="cyan")
    app_table.add_column("Value", style="white")

    app_info = results.app_info
    app_table.add_row("Name", app_info.name)
    app_table.add_row("Package Name", app_info.package_name)
    app_table.add_row("Version", f"{app_info.version} ({app_info.build})")

    console.print(app_table)
    console.print()


def _print_ios_summary(results: IOSAnalysisResults) -> None:
    """Print a brief summary of the analysis."""
    file_analysis = results.file_analysis
    binary_analysis = results.binary_analysis

    console.print("\n[bold]Summary:[/bold]")
    console.print(f"• App name: [cyan]{results.app_info.name}[/cyan]")
    console.print(f"• Total app size: [cyan]{_format_bytes(file_analysis.total_size)}[/cyan]")
    console.print(f"• File count: [cyan]{file_analysis.file_count:,}[/cyan]")

    if file_analysis.duplicate_files:
        console.print(
            f"• Potential savings from duplicates: "
            f"[yellow]{_format_bytes(file_analysis.total_duplicate_savings)}[/yellow]"
        )

    if binary_analysis:
        for binary in binary_analysis:
            console.print(f"\nExecutable Size: {binary.executable_size / 1024 / 1024:.1f} MB")
            console.print(f"Architectures: {', '.join(binary.architectures)}")
            console.print(f"Linked Libraries: {len(binary.linked_libraries)}")
            console.print(f"Sections: {len(binary.sections)}")


def _format_bytes(size: int) -> str:
    """Format byte size in human-readable format."""
    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size_float < 1024.0:
            return f"{size_float:.1f} {unit}"
        size_float /= 1024.0
    return f"{size_float:.1f} TB"


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
