from contextlib import ExitStack
from pathlib import Path
from typing import Dict, TextIO

import click

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from launchpad.size.models.android import AndroidAnalysisResults
from launchpad.size.models.apple import AppleAnalysisResults
from launchpad.size.models.common import BaseAnalysisResults, FileAnalysis
from launchpad.size.runner import do_size, write_results_as_json
from launchpad.utils.console import console
from launchpad.utils.logging import setup_logging
from launchpad.utils.performance import GLOBAL_REGISTRY


@click.command(name="size")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="INPUT_PATH")
@click.option(
    "-o",
    "--output",
    default="-",
    show_default=True,
    type=click.File("w"),
    help="Output path for the analysis.",
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
@click.option(
    "--working-dir",
    type=click.Path(path_type=Path),
    help="Working directory for temporary files (default: system temp).",
)
@click.option("--skip-swift-metadata", is_flag=True, help="Skip Swift metadata parsing for faster analysis.")
@click.option("--skip-symbols", is_flag=True, help="Skip symbol extraction and analysis.")
@click.option(
    "--skip-component-analysis", is_flag=True, help="Skip detailed binary component analysis for faster processing."
)
@click.option("--skip-treemap", is_flag=True, help="Skip treemap generation for hierarchical size analysis.")
def size_command(
    input_path: Path,
    output: TextIO,
    verbose: bool,
    working_dir: Path | None,
    skip_swift_metadata: bool,
    skip_symbols: bool,
    skip_component_analysis: bool,
    skip_treemap: bool,
    quiet: bool,
    output_format: str,
) -> None:
    """Analyze provided artifact and generate a size report."""
    setup_logging(verbose=verbose, quiet=quiet)

    GLOBAL_REGISTRY.clear()

    if verbose and quiet:
        raise click.UsageError("Cannot specify both --verbose and --quiet")

    if not quiet:
        console.print("[bold blue]Size Analyzer[/bold blue]")
        console.print(f"Analyzing: [cyan]{input_path}[/cyan]")
        console.print(f"Output: [cyan]{output.name}[/cyan]")
        console.print()

    flags: Dict[str, Path | bool] = {}
    flags["skip_swift_metadata"] = skip_swift_metadata
    flags["skip_symbols"] = skip_symbols
    flags["skip_component_analysis"] = skip_component_analysis
    flags["skip_treemap"] = skip_treemap
    if working_dir:
        flags["working_dir"] = working_dir

    try:
        with ExitStack() as stack:
            progress = stack.enter_context(
                Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    disable=quiet,
                )
            )

            task = progress.add_task("Analyzing...", total=None)
            results = do_size(input_path, **flags)
            if output_format == "json":
                write_results_as_json(results, output)
            else:
                _print_results_as_table(results)

            if isinstance(results, AppleAnalysisResults) and not quiet:
                _print_apple_summary(results)

            progress.update(task, description="Analysis complete!")

    except Exception:
        console.print_exception()
        raise click.Abort()
    finally:
        GLOBAL_REGISTRY.log_summary("cli.size")


def _print_results_as_table(results: BaseAnalysisResults) -> None:
    if isinstance(results, AndroidAnalysisResults):
        _print_android_table_output(results)
    elif isinstance(results, AppleAnalysisResults):
        _print_apple_table_output(results)
    else:
        raise ValueError(f"Unknown results kind {results}")


def _print_apple_table_output(results: AppleAnalysisResults) -> None:
    """Print results in table format to console."""

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

    file_analysis = results.file_analysis
    _print_file_analysis_table(file_analysis)

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


def _print_android_table_output(results: AndroidAnalysisResults) -> None:
    """Print results in table format to console."""

    app_table = Table(title="App Information", show_header=True, header_style="bold magenta")
    app_table.add_column("Property", style="cyan")
    app_table.add_column("Value")

    app_info = results.app_info
    app_table.add_row("Name", app_info.name)
    app_table.add_row("Package Name", app_info.package_name)
    app_table.add_row("Version", f"{app_info.version} ({app_info.build})")

    console.print(app_table)
    console.print()

    _print_file_analysis_table(results.file_analysis)


def _print_file_analysis_table(file_analysis: FileAnalysis) -> None:
    file_table = Table(title="File Analysis", show_header=True, header_style="bold green")
    file_table.add_column("Metric", style="cyan")
    file_table.add_column("Value")

    file_table.add_row("Total Size", _format_bytes(file_analysis.total_size))
    file_table.add_row("File Count", str(file_analysis.file_count))

    console.print(file_table)
    console.print()


def _print_apple_summary(results: AppleAnalysisResults) -> None:
    """Print a brief summary of the analysis."""
    file_analysis = results.file_analysis
    binary_analysis = results.binary_analysis
    insights = results.insights

    console.print("\n[bold]Summary:[/bold]")
    console.print(f"• App name: [cyan]{results.app_info.name}[/cyan]")
    console.print(f"• Total app size: [cyan]{_format_bytes(file_analysis.total_size)}[/cyan]")
    console.print(f"• File count: [cyan]{file_analysis.file_count:,}[/cyan]")

    if insights and insights.duplicate_files and insights.duplicate_files.total_savings > 0:
        console.print(
            f"• Potential savings from duplicates: "
            f"[yellow]{_format_bytes(insights.duplicate_files.total_savings)}[/yellow]"
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
