"""Logging utilities for app size analyzer."""

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler


class StructuredRichHandler(RichHandler):
    """RichHandler that shows structured logging extras."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        # Default attributes to ignore
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "getMessage",
            "exc_info",
            "exc_text",
            "stack_info",
            "message",
            "taskName",
        }

        extras = {k: v for k, v in record.__dict__.items() if k not in standard_attrs and not k.startswith("_")}

        if extras:
            extra_parts = []
            for key, value in extras.items():
                extra_parts.append(f"[dim]{key}[/dim]=[yellow]{value}[/yellow]")

            if extra_parts:
                message += f" [dim]|[/dim] {' '.join(extra_parts)}"

        return message


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
                StructuredRichHandler(
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
            handlers=[logging.StreamHandler(sys.stdout)],
        )

    # Set levels for third-party libraries
    if not verbose:
        logging.getLogger("lief").setLevel(logging.WARNING)

    # Set levels for third-party libraries
    logging.getLogger("datadog.dogstatsd").setLevel(logging.ERROR)
    logging.getLogger("arroyo.processing.processor").setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name."""
    return logging.getLogger(name)
