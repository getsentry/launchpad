"""Performance tracing utilities for measuring code execution time."""

from __future__ import annotations

import functools
import time

from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, TypeVar

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class PerformanceTracer:
    """Performance tracer for measuring code execution time.

    This class provides both context manager and decorator interfaces for timing
    code sections. It's designed to be easily replaceable with Sentry tracing
    or other performance monitoring systems.
    """

    def __init__(self, name: str, logger_name: str | None = None) -> None:
        """Initialize the performance tracer.

        Args:
            name: Name of the operation being traced
            logger_name: Optional logger name for custom logging
        """
        self.name = name
        self.logger = get_logger(logger_name) if logger_name else logger
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.duration: float | None = None
        self.metadata: Dict[str, Any] = {}

    def __enter__(self) -> PerformanceTracer:
        """Start timing when entering context."""
        self.start_time = time.time()
        # No logging during execution - completely silent
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """End timing when exiting context."""
        if self.start_time is not None:
            self.end_time = time.time()
            self.duration = self.end_time - self.start_time

            # Only log exceptions, not successful completions
            if exc_type is not None:
                self.logger.warning(f"Failed: {self.name} (took {self.duration:.3f}s)")
            # No logging for successful completions - completely silent

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the trace.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def get_duration(self) -> float | None:
        """Get the duration of the trace.

        Returns:
            Duration in seconds, or None if not completed
        """
        return self.duration


def trace(name: str | None = None, logger_name: str | None = None) -> Callable[[F], F]:
    """Decorator for tracing function execution time.

    Args:
        name: Name of the operation being traced (auto-detected from function if None)
        logger_name: Optional logger name for custom logging

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Auto-detect name from function if not provided
            trace_name = name or f"{func.__module__}.{func.__qualname__}"
            with PerformanceTracer(trace_name, logger_name):
                result = func(*args, **kwargs)
                return result

        return wrapper  # type: ignore

    return decorator


@contextmanager
def trace_context(name: str | None = None, logger_name: str | None = None) -> Generator[PerformanceTracer, None, None]:
    """Context manager for tracing code sections.

    Args:
        name: Name of the operation being traced (auto-detected from caller if None)
        logger_name: Optional logger name for custom logging

    Yields:
        PerformanceTracer instance for adding metadata
    """
    # Auto-detect name from caller if not provided
    if name is None:
        import inspect

        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller_frame = frame.f_back
            module = caller_frame.f_globals.get("__name__", "unknown")
            function = caller_frame.f_code.co_name
            name = f"{module}.{function}"
        else:
            name = "unknown_operation"

    with PerformanceTracer(name, logger_name) as tracer:
        yield tracer


class PerformanceRegistry:
    """Registry for collecting and reporting performance metrics.

    This class can be used to collect timing data across multiple operations
    and generate summary reports.
    """

    def __init__(self) -> None:
        """Initialize the performance registry."""
        self.traces: Dict[str, float] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}

    def record_trace(self, name: str, duration: float, metadata: Dict[str, Any] | None = None) -> None:
        """Record a completed trace.

        Args:
            name: Name of the trace
            duration: Duration in seconds
            metadata: Optional metadata for the trace
        """
        self.traces[name] = duration
        if metadata:
            self.metadata[name] = metadata

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all recorded traces.

        Returns:
            Dictionary containing trace summary
        """
        if not self.traces:
            return {"total_traces": 0, "total_duration": 0.0}

        total_duration = sum(self.traces.values())
        sorted_traces = sorted(self.traces.items(), key=lambda x: x[1], reverse=True)

        return {
            "total_traces": len(self.traces),
            "total_duration": total_duration,
            "traces": dict(sorted_traces),
            "metadata": self.metadata,
        }

    def log_summary(self, logger_name: str | None = None) -> None:
        """Log a summary of all recorded traces.

        Args:
            logger_name: Optional logger name for custom logging
        """
        summary = self.get_summary()
        log = get_logger(logger_name) if logger_name else logger

        if summary["total_traces"] == 0:
            log.info("No performance traces recorded")
            return

        log.info("=" * 60)
        log.info("PERFORMANCE SUMMARY")
        log.info("=" * 60)
        log.info(f"Total traces: {summary['total_traces']}")
        log.info(f"Total duration: {summary['total_duration']:.3f}s")
        log.info("-" * 60)

        for name, duration in summary["traces"].items():
            percentage = (duration / summary["total_duration"]) * 100
            log.info(f"{name}: {duration:.3f}s ({percentage:.1f}%)")

        log.info("=" * 60)

    def log_summary_if_traces(self, logger_name: str | None = None) -> None:
        """Log a summary only if there are traces recorded.

        This is useful for automatically logging summaries at the end of operations
        without cluttering logs when no tracing was done.

        Args:
            logger_name: Optional logger name for custom logging
        """
        if self.traces:
            self.log_summary(logger_name)

    def get_formatted_summary(self) -> str:
        """Get a formatted string summary of all recorded traces.

        Returns:
            Formatted summary string
        """
        summary = self.get_summary()

        if summary["total_traces"] == 0:
            return "No performance traces recorded"

        lines = [
            "=" * 60,
            "PERFORMANCE SUMMARY",
            "=" * 60,
            f"Total traces: {summary['total_traces']}",
            f"Total duration: {summary['total_duration']:.3f}s",
            "-" * 60,
        ]

        for name, duration in summary["traces"].items():
            percentage = (duration / summary["total_duration"]) * 100
            lines.append(f"{name}: {duration:.3f}s ({percentage:.1f}%)")

        lines.append("=" * 60)
        return "\n".join(lines)

    def clear(self) -> None:
        """Clear all recorded traces."""
        self.traces.clear()
        self.metadata.clear()


# Global registry instance for convenience
_global_registry = PerformanceRegistry()


def get_global_registry() -> PerformanceRegistry:
    """Get the global performance registry.

    Returns:
        Global PerformanceRegistry instance
    """
    return _global_registry


def log_global_summary(logger_name: str | None = None) -> None:
    """Log a summary of the global registry if there are traces.

    This is a convenience function to automatically log performance summaries
    at the end of operations without cluttering logs when no tracing was done.

    Args:
        logger_name: Optional logger name for custom logging
    """
    _global_registry.log_summary_if_traces(logger_name)


def get_global_summary() -> str:
    """Get a formatted summary of the global registry.

    Returns:
        Formatted summary string
    """
    return _global_registry.get_formatted_summary()


def clear_global_registry() -> None:
    """Clear the global registry.

    Useful for resetting between different operations.
    """
    _global_registry.clear()


def trace_with_registry(
    name: str | None = None, registry: PerformanceRegistry | None = None, logger_name: str | None = None
) -> Callable[[F], F]:
    """Decorator for tracing function execution time and recording to registry.

    Args:
        name: Name of the operation being traced (auto-detected from function if None)
        registry: PerformanceRegistry to record to (uses global if None)
        logger_name: Optional logger name for custom logging

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            reg = registry or _global_registry
            # Auto-detect name from function if not provided
            trace_name = name or f"{func.__module__}.{func.__qualname__}"
            with PerformanceTracer(trace_name, logger_name) as tracer:
                result = func(*args, **kwargs)
            # Check duration after context exit
            if tracer.duration is not None:
                reg.record_trace(trace_name, tracer.duration, tracer.metadata)
            return result

        return wrapper  # type: ignore

    return decorator


@contextmanager
def trace_context_with_registry(
    name: str | None = None, registry: PerformanceRegistry | None = None, logger_name: str | None = None
) -> Generator[PerformanceTracer, None, None]:
    """Context manager for tracing code sections and recording to registry.

    Args:
        name: Name of the operation being traced (auto-detected from caller if None)
        registry: PerformanceRegistry to record to (uses global if None)
        logger_name: Optional logger name for custom logging

    Yields:
        PerformanceTracer instance for adding metadata
    """
    reg = registry or _global_registry

    # Auto-detect name from caller if not provided
    if name is None:
        import inspect

        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller_frame = frame.f_back
            module = caller_frame.f_globals.get("__name__", "unknown")
            function = caller_frame.f_code.co_name
            name = f"{module}.{function}"
        else:
            name = "unknown_operation"

    with PerformanceTracer(name, logger_name) as tracer:
        yield tracer
        if tracer.duration is not None:
            reg.record_trace(name, tracer.duration, tracer.metadata)
