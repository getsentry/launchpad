"""Performance tracing utilities for measuring code execution time."""

from __future__ import annotations

import functools
import threading
import time

from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, TypeVar

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Thread-local storage for tracking call hierarchy
_trace_stack = threading.local()


def _get_trace_stack() -> list[str]:
    """Get the current trace stack for this thread."""
    if not hasattr(_trace_stack, "stack"):
        stack: list[str] = []
        _trace_stack.stack = stack
    return _trace_stack.stack


def _get_current_parent() -> str | None:
    """Get the current parent trace name."""
    stack = _get_trace_stack()
    return stack[-1] if stack else None


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
        # Push this trace onto the stack
        _get_trace_stack().append(self.name)
        self.start_time = time.time()
        # No logging during execution - completely silent
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """End timing when exiting context."""
        # Pop this trace from the stack
        stack = _get_trace_stack()
        if stack and stack[-1] == self.name:
            stack.pop()

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
        self.traces: Dict[str, list[float]] = {}
        self.metadata: Dict[str, list[Dict[str, Any]]] = {}
        self.hierarchy: Dict[str, Dict[str, list[float]]] = {}  # parent -> {child -> [durations]}

    def record_trace(self, name: str, duration: float, metadata: Dict[str, Any] | None = None) -> None:
        """Record a completed trace.

        Args:
            name: Name of the trace
            duration: Duration in seconds
            metadata: Optional metadata for the trace
        """
        if name not in self.traces:
            self.traces[name] = []
            self.metadata[name] = []

        self.traces[name].append(duration)
        if metadata:
            self.metadata[name].append(metadata)
        else:
            self.metadata[name].append({})

        # Record hierarchy
        parent = _get_current_parent()
        if parent and parent != name:  # Avoid self-parenting
            if parent not in self.hierarchy:
                self.hierarchy[parent] = {}
            if name not in self.hierarchy[parent]:
                self.hierarchy[parent][name] = []
            self.hierarchy[parent][name].append(duration)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all recorded traces.

        Returns:
            Dictionary containing trace summary with aggregate statistics
        """
        if not self.traces:
            return {"total_traces": 0, "total_duration": 0.0, "trace_stats": {}}

        # Calculate aggregate stats for each trace name
        trace_stats: Dict[str, Dict[str, float]] = {}
        total_execution_count = 0
        all_durations: list[float] = []

        for name, durations in self.traces.items():
            if durations:  # Only process if we have durations
                total_execution_count += len(durations)
                all_durations.extend(durations)

                trace_stats[name] = {
                    "total": sum(durations),
                    "count": len(durations),
                    "min": min(durations),
                    "max": max(durations),
                    "avg": sum(durations) / len(durations),
                }

        total_duration = sum(all_durations) if all_durations else 0.0

        # Sort by total time (descending)
        sorted_trace_stats = dict(sorted(trace_stats.items(), key=lambda x: x[1]["total"], reverse=True))

        return {
            "total_traces": len(self.traces),
            "total_executions": total_execution_count,
            "total_duration": total_duration,
            "trace_stats": sorted_trace_stats,
            "metadata": self.metadata,
        }

    def get_hierarchical_summary(self) -> Dict[str, Any]:
        """Get a hierarchical summary showing parent-child relationships and self-time.

        Returns:
            Dictionary containing hierarchical trace summary
        """
        if not self.traces:
            return {"total_traces": 0, "total_duration": 0.0, "hierarchy": {}}

        # Calculate basic stats for all traces
        trace_stats: Dict[str, Dict[str, Any]] = {}
        total_execution_count = 0

        for name, durations in self.traces.items():
            if durations:
                total_execution_count += len(durations)

                trace_stats[name] = {
                    "total": sum(durations),
                    "count": len(durations),
                    "min": min(durations),
                    "max": max(durations),
                    "avg": sum(durations) / len(durations),
                    "self": sum(durations),  # Will be adjusted below
                }

        # Calculate self time (subtract children time from total time)
        for parent, children in self.hierarchy.items():
            if parent in trace_stats:
                children_total = sum(sum(child_durations) for child_durations in children.values())
                trace_stats[parent]["self"] = trace_stats[parent]["total"] - children_total

                # Store children info
                trace_stats[parent]["children"] = {}
                for child, child_durations in children.items():
                    if child_durations:
                        trace_stats[parent]["children"][child] = {
                            "total": sum(child_durations),
                            "count": len(child_durations),
                            "min": min(child_durations),
                            "max": max(child_durations),
                            "avg": sum(child_durations) / len(child_durations),
                        }

        # Find root traces (traces that are not children of any other trace)
        all_children: set[str] = set()
        for children in self.hierarchy.values():
            all_children.update(children.keys())

        roots = [name for name in trace_stats.keys() if name not in all_children]

        # Calculate total duration from root traces only (to avoid double-counting)
        total_duration = sum(trace_stats[root]["total"] for root in roots) if roots else 0.0

        return {
            "total_traces": len(self.traces),
            "total_executions": total_execution_count,
            "total_duration": total_duration,
            "trace_stats": trace_stats,
            "roots": roots,
            "hierarchy": self.hierarchy,
        }

    def log_hierarchical_summary(self, logger_name: str | None = None) -> None:
        """Log a hierarchical summary of all recorded traces.

        Args:
            logger_name: Optional logger name for custom logging
        """
        summary = self.get_hierarchical_summary()
        log = get_logger(logger_name) if logger_name else logger

        if summary["total_traces"] == 0:
            log.info("No performance traces recorded")
            return

        log.info("=" * 60)
        log.info("HIERARCHICAL PERFORMANCE SUMMARY")
        log.info("=" * 60)
        log.info(f"Total traces: {summary['total_traces']}")
        log.info(f"Total executions: {summary['total_executions']}")
        log.info(f"Total duration: {summary['total_duration']:.3f}s")
        log.info("-" * 60)

        def log_trace_tree(
            name: str, stats: Dict[str, Any], indent: int = 0, is_last: bool = True, prefix: str = ""
        ) -> None:
            # Build the tree prefix
            if indent == 0:
                tree_prefix = ""
            else:
                tree_prefix = prefix + ("└── " if is_last else "├── ")

            percentage = (stats["total"] / summary["total_duration"]) * 100
            self_percentage = (stats["self"] / summary["total_duration"]) * 100

            if stats["count"] == 1:
                if stats["self"] != stats["total"]:
                    log.info(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%), self: {stats['self']:.3f}s ({self_percentage:.1f}%)"
                    )
                else:
                    log.info(f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%)")
            else:
                if stats["self"] != stats["total"]:
                    log.info(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%) [{stats['count']}x, avg: {stats['avg']:.3f}s], self: {stats['self']:.3f}s ({self_percentage:.1f}%)"
                    )
                else:
                    log.info(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%) [{stats['count']}x, avg: {stats['avg']:.3f}s]"
                    )

            # Log children
            children = stats.get("children", {})
            if children:
                sorted_children = sorted(children.items(), key=lambda x: x[1]["total"], reverse=True)
                for i, (child_name, child_stats) in enumerate(sorted_children):
                    is_last_child = i == len(sorted_children) - 1

                    # Build prefix for child's children
                    child_prefix = prefix + ("    " if is_last else "│   ")

                    child_stats_full = summary["trace_stats"].get(child_name, child_stats)
                    log_trace_tree(child_name, child_stats_full, indent + 1, is_last_child, child_prefix)

        # Log root traces and their trees
        for root in sorted(summary["roots"], key=lambda x: summary["trace_stats"][x]["total"], reverse=True):
            log_trace_tree(root, summary["trace_stats"][root])

        log.info("=" * 60)

    def log_summary(self, logger_name: str | None = None) -> None:
        """Log a summary of all recorded traces (uses hierarchical display).

        Args:
            logger_name: Optional logger name for custom logging
        """
        # Use hierarchical summary by default
        self.log_hierarchical_summary(logger_name)

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
        summary = self.get_hierarchical_summary()

        if summary["total_traces"] == 0:
            return "No performance traces recorded"

        lines = [
            "=" * 60,
            "HIERARCHICAL PERFORMANCE SUMMARY",
            "=" * 60,
            f"Total traces: {summary['total_traces']}",
            f"Total executions: {summary['total_executions']}",
            f"Total duration: {summary['total_duration']:.3f}s",
            "-" * 60,
        ]

        def format_trace_tree(
            name: str, stats: Dict[str, Any], indent: int = 0, is_last: bool = True, prefix: str = ""
        ) -> None:
            # Build the tree prefix
            if indent == 0:
                tree_prefix = ""
            else:
                tree_prefix = prefix + ("└── " if is_last else "├── ")

            percentage = (stats["total"] / summary["total_duration"]) * 100
            self_percentage = (stats["self"] / summary["total_duration"]) * 100

            if stats["count"] == 1:
                if stats["self"] != stats["total"]:
                    lines.append(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%), self: {stats['self']:.3f}s ({self_percentage:.1f}%)"
                    )
                else:
                    lines.append(f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%)")
            else:
                if stats["self"] != stats["total"]:
                    lines.append(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%) [{stats['count']}x, avg: {stats['avg']:.3f}s], self: {stats['self']:.3f}s ({self_percentage:.1f}%)"
                    )
                else:
                    lines.append(
                        f"{tree_prefix}{name}: {stats['total']:.3f}s ({percentage:.1f}%) [{stats['count']}x, avg: {stats['avg']:.3f}s]"
                    )

            # Process children
            children = stats.get("children", {})
            if children:
                sorted_children = sorted(children.items(), key=lambda x: x[1]["total"], reverse=True)
                for i, (child_name, child_stats) in enumerate(sorted_children):
                    is_last_child = i == len(sorted_children) - 1

                    # Build prefix for child's children
                    child_prefix = prefix + ("    " if is_last else "│   ")

                    child_stats_full = summary["trace_stats"].get(child_name, child_stats)
                    format_trace_tree(child_name, child_stats_full, indent + 1, is_last_child, child_prefix)

        # Add root traces and their trees
        for root in sorted(summary["roots"], key=lambda x: summary["trace_stats"][x]["total"], reverse=True):
            format_trace_tree(root, summary["trace_stats"][root])

        lines.append("=" * 60)
        return "\n".join(lines)

    def clear(self) -> None:
        """Clear all recorded traces."""
        self.traces.clear()
        self.metadata.clear()
        self.hierarchy.clear()


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

    # Record to registry after tracer context has completed and duration is set
    if tracer.duration is not None:
        reg.record_trace(name, tracer.duration, tracer.metadata)
