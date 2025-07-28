from __future__ import annotations

from pathlib import Path

import click

from ..utils.android.apksigner import Apksigner, ApksignerError
from ..utils.console import console
from ..utils.logging import setup_logging


@click.command("distribution")
@click.argument("apk_path", type=click.Path(exists=True, path_type=Path))
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging output.")
def distribution_command(apk_path: Path, verbose: bool) -> None:
    """Print certificate information for an APK file.

    Uses apksigner to extract and display the certificate information
    from the specified APK file.
    """
    setup_logging(verbose=verbose, quiet=False)

    if not apk_path.suffix.lower() == ".apk":
        console.print(f"[bold red]Error:[/bold red] File must be an APK file, got: {apk_path.suffix}")
        raise click.Abort()

    console.print(f"[bold blue]Analyzing APK certificate:[/bold blue] {apk_path}")

    try:
        apksigner = Apksigner()
        cert_info = apksigner.get_certs(apk_path)
        console.print("\n[bold green]Certificate Information:[/bold green]")
        console.print(cert_info)
    except ApksignerError as e:
        console.print(f"[bold red]Error running apksigner:[/bold red] {e}")
        if verbose:
            console.print(f"Return code: {e.returncode}")
            console.print(f"Stdout: {e.stdout}")
            console.print(f"Stderr: {e.stderr}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if verbose:
            console.print_exception()
        raise click.Abort()
