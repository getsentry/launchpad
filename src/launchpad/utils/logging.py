"""Logging utilities for app size analyzer."""

import json
import logging
import sys

from datetime import datetime, timezone
from typing import Any, Dict

from rich.console import Console
from rich.logging import RichHandler

from launchpad.tracing import RequestLogFilter

# Standard LogRecord attributes to exclude from extra fields
STANDARD_LOG_ATTRS = {
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
    "asctime",
}


def get_extra_fields(record: logging.LogRecord) -> Dict[str, Any]:
    """Extract extra fields from a log record, excluding standard LogRecord attributes."""
    return {k: v for k, v in record.__dict__.items() if k not in STANDARD_LOG_ATTRS and not k.startswith("_")}


class StructuredRichHandler(RichHandler):
    """RichHandler that shows structured logging extras."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        extras = get_extra_fields(record)

        if extras:
            extra_parts = []
            for key, value in extras.items():
                extra_parts.append(f"[dim]{key}[/dim]=[yellow]{value}[/yellow]")

            if extra_parts:
                message += f" [dim]|[/dim] {' '.join(extra_parts)}"

        return message


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging in production environments."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        extra_fields = get_extra_fields(record)
        if extra_fields:
            log_entry.update(extra_fields)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        try:
            return json.dumps(log_entry, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            log_entry["message"] = str(record.getMessage())
            return json.dumps(log_entry, default=str, ensure_ascii=False)


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
        handler = StructuredRichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.addFilter(RequestLogFilter())

        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[handler],
        )
    else:
        # Use JSON formatting for non-terminal environments (e.g., GCP logs)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        handler.addFilter(RequestLogFilter())

        logging.basicConfig(
            level=level,
            handlers=[handler],
        )

    # Set levels for third-party libraries
    if not verbose:
        logging.getLogger("lief").setLevel(logging.WARNING)

    # Set levels for third-party libraries
    logging.getLogger("datadog.dogstatsd").setLevel(logging.ERROR)
    logging.getLogger("arroyo.processing.processor").setLevel(logging.ERROR)
    logging.getLogger("arroyo.processing.strategies.run_task_with_multiprocessing").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name."""
    return logging.getLogger(name)
