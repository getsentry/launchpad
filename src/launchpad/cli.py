from __future__ import annotations

import asyncio
import logging
import os

import click

from . import __version__
from .service import run_service
from .size.cli import size_command
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
        logging.getLogger("aiohttp.access").setLevel(logging.INFO)

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


cli.add_command(size_command)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
