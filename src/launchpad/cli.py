from __future__ import annotations

import os

import click

from . import __version__
from .distribution.cli import distribution_command
from .size.cli import app_icon_command, diff_command, profile_dex_parsing_command, size_command
from .utils.console import console
from .utils.logging import setup_logging


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version information and exit.")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """Launchpad - Analyze Apple and Android app bundle sizes."""
    if version:
        click.echo(f"Launchpad v{__version__}")
        ctx.exit()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--processing-pool-name", default="launchpad", help="Name of the processing pool.", show_default=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
def worker(
    processing_pool_name: str,
    verbose: bool,
) -> None:
    """Start the Launchpad TaskWorker.

    Runs the TaskWorker only, without an HTTP server.
    Requires LAUNCHPAD_WORKER_RPC_HOST and LAUNCHPAD_WORKER_CONCURRENCY env vars.
    """
    from .worker.config import run_worker

    region = os.getenv("SENTRY_REGION", None)
    mode = "development" if region is None else "production"
    os.environ["LAUNCHPAD_ENV"] = mode

    if not verbose and mode == "development":
        verbose = True

    setup_logging(verbose=verbose, quiet=False)

    console.print(f"[bold blue]Launchpad TaskWorker v{__version__}[/bold blue]")
    console.print("Press Ctrl+C to stop the worker")
    console.print()

    try:
        run_worker(
            processing_pool_name=processing_pool_name,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Worker stopped by user[/yellow]")
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Worker error:[/bold red] {e}")
        if verbose:
            console.print_exception()
        raise click.Abort()


cli.add_command(size_command)
cli.add_command(diff_command)
cli.add_command(app_icon_command)
cli.add_command(distribution_command)
cli.add_command(profile_dex_parsing_command)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
