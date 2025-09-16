"""Logging utilities for app size analyzer."""

import json
import logging
import sys

from datetime import datetime
from typing import Any, Dict

from rich.console import Console
from rich.logging import RichHandler

from launchpad.tracing import RequestLogFilter


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


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging in production environments."""

    # Standard LogRecord attributes to exclude from extra fields
    STANDARD_ATTRS = {
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

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with structured fields."""
        # Create base log entry
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add location information
        if record.pathname:
            log_entry["source"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add any extra fields from logger.info(..., extra={...})
        extra_fields = {
            k: v for k, v in record.__dict__.items() if k not in self.STANDARD_ATTRS and not k.startswith("_")
        }
        if extra_fields:
            log_entry.update(extra_fields)

        # Handle exceptions
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Convert to JSON string
        try:
            return json.dumps(log_entry, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Fallback to string representation if JSON serialization fails
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
        # This enables structured logging with extra fields
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


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name."""
    return logging.getLogger(name)
