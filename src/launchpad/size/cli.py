from pathlib import Path
from typing import Dict, TextIO

import click

from rich.table import Table

from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.parsers.android.dex.dex_file_parser import DexFileParser
from launchpad.parsers.android.dex.dex_mapping import DexMapping
from launchpad.size.models.android import AndroidAnalysisResults
from launchpad.size.models.apple import AppleAnalysisResults
from launchpad.size.models.common import BaseAnalysisResults, FileAnalysis
from launchpad.size.runner import do_size, write_results_as_json
from launchpad.utils.console import console
from launchpad.utils.logging import setup_logging


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
@click.option(
    "--skip-swift-metadata",
    is_flag=True,
    help="Skip Swift metadata parsing for faster analysis.",
)
@click.option("--skip-symbols", is_flag=True, help="Skip symbol extraction and analysis.")
@click.option(
    "--skip-component-analysis",
    is_flag=True,
    help="Skip detailed binary component analysis for faster processing.",
)
@click.option(
    "--skip-treemap",
    is_flag=True,
    help="Skip treemap generation for hierarchical size analysis.",
)
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
        results = do_size(input_path, **flags)
        if output_format == "json":
            write_results_as_json(results, output)
        else:
            _print_results_as_table(results)

    except Exception:
        console.print_exception()
        raise click.Abort()


@click.command(name="app-icon")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="INPUT_PATH")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Output path for the icon.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except errors.")
def app_icon_command(
    input_path: Path,
    output: Path | None,
    verbose: bool,
    quiet: bool,
) -> None:
    """Extract app icon from provided artifact."""
    setup_logging(verbose=verbose, quiet=quiet)

    if verbose and quiet:
        raise click.UsageError("Cannot specify both --verbose and --quiet")

    if output is None:
        raise click.UsageError("Missing required option '--output' / '-o'")

    if not quiet:
        console.print("[bold blue]App Icon[/bold blue]")
        console.print(f"Extracting app icon from: [cyan]{input_path}[/cyan]")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print()

    artifact = ArtifactFactory.from_path(input_path)
    app_icon = artifact.get_app_icon()
    if app_icon:
        with open(output, "wb") as f:
            f.write(app_icon)
        console.print(f"App icon extracted to: [cyan]{output}[/cyan]")
    else:
        console.print("No app icon found")
        raise click.Abort()


@click.command(name="profile-dex-parsing")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="DEX_PATH")
@click.argument("mapping_path", required=False, type=click.Path(exists=True, path_type=Path), metavar="MAPPING_PATH")
def profile_dex_parsing_command(input_path: Path, mapping_path: Path | None = None):
    mapping = None
    if mapping_path:
        with open(mapping_path, "rb") as f:
            mapping = DexMapping(f.read())
    with open(input_path, "rb") as f:
        parser = DexFileParser(f.read(), mapping)

    parser.get_class_definitions()


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
    app_table.add_row("Bundle ID", app_info.app_id)
    app_table.add_row("Version", f"{app_info.version} ({app_info.build})")
    app_table.add_row("Min OS", app_info.minimum_os_version)
    app_table.add_row("Platforms", ", ".join(app_info.supported_platforms))

    console.print(app_table)
    console.print()

    _print_file_analysis_table(results.file_analysis)


def _print_android_table_output(results: AndroidAnalysisResults) -> None:
    """Print results in table format to console."""

    app_table = Table(title="App Information", show_header=True, header_style="bold magenta")
    app_table.add_column("Property", style="cyan")
    app_table.add_column("Value")

    app_info = results.app_info
    app_table.add_row("Name", app_info.name)
    app_table.add_row("Package Name", app_info.app_id)
    app_table.add_row("Version", f"{app_info.version} ({app_info.build})")

    console.print(app_table)
    console.print()

    _print_file_analysis_table(results.file_analysis)


def _print_file_analysis_table(file_analysis: FileAnalysis) -> None:
    file_table = Table(title="File Analysis", show_header=True, header_style="bold green")
    file_table.add_column("Metric", style="cyan")
    file_table.add_column("Value")

    file_table.add_row("Total Size", _format_bytes(file_analysis.total_size))
    file_table.add_row("File Count", str(len(file_analysis.files)))

    console.print(file_table)
    console.print()


def _format_bytes(size: int) -> str:
    """Format byte size in human-readable format."""
    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size_float < 1024.0:
            return f"{size_float:.1f} {unit}"
        size_float /= 1024.0
    return f"{size_float:.1f} TB"
