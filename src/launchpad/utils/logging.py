"""Logging utilities for app size analyzer."""

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Setup logging configuration.

    Args:
        verbose: Enable debug-level logging
        quiet: Suppress all logging except errors
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    console = Console()

    if console.is_terminal:
        # Use rich for colored terminal output _only_ for terminal output
        # We don't want to make server logs unreadable
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[
                RichHandler(
                    console=console,
                    show_time=True,
                    show_path=False,
                    markup=True,
                    rich_tracebacks=True,
                )
            ],
        )
    else:
        # Fall back to standard logging for non-terminal environments
        # (e.g., when output is redirected to a file or sent to Datadog)
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stderr)],
        )

    # Set levels for third-party libraries
    if not verbose:
        logging.getLogger("lief").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name."""
    return logging.getLogger(name)
