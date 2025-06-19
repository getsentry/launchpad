from contextlib import ExitStack
from pathlib import Path
from typing import TextIO

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..utils import console, setup_logging
from .analysis import do_size_analysis


@click.command(name="size")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path), metavar="INPUT_PATH")
@click.option(
    "-o",
    "--output",
    type=click.File("w"),
    help="Output path for the JSON analysis report (default: stdout).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except errors.")
def size_command(
    input_path: Path,
    output: TextIO,
    working_dir: Path | None,
    verbose: bool,
    quiet: bool,
) -> None:
    """Analyze provided artifact and generate a size report."""
    setup_logging(verbose=verbose, quiet=quiet)

    if verbose and quiet:
        raise click.UsageError("Cannot specify both --verbose and --quiet")

    if not quiet:
        console.print("[bold blue]Size Analyzer[/bold blue]")
        console.print(f"Analyzing: [cyan]{input_path}[/cyan]")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print()

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

            input_file = stack.enter_context(open(input_path, "rb"))

            task = progress.add_task("Analyzing...", total=None)
            do_size_analysis(input_file, output)
            progress.update(task, description="Analysis complete!")

    except Exception:
        console.print_exception()
        raise click.Abort()
