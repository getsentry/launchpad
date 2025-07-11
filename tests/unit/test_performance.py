"""Tests for performance tracing utilities."""

import time

import pytest

from launchpad.utils.performance import (
    PerformanceRegistry,
    PerformanceTracer,
    clear_global_registry,
    get_global_registry,
    get_global_summary,
    log_global_summary,
    trace,
    trace_context,
    trace_context_with_registry,
    trace_with_registry,
)


class TestPerformanceTracer:
    """Test the PerformanceTracer class."""

    def test_basic_timing(self) -> None:
        """Test basic timing functionality."""
        with PerformanceTracer("test_operation") as tracer:
            time.sleep(0.01)  # Small delay to ensure measurable time

        assert tracer.duration is not None
        assert tracer.duration > 0
        assert tracer.name == "test_operation"

    def test_metadata(self) -> None:
        """Test metadata functionality."""
        with PerformanceTracer("test_operation") as tracer:
            tracer.add_metadata("key1", "value1")
            tracer.add_metadata("key2", 42)

        assert tracer.metadata["key1"] == "value1"
        assert tracer.metadata["key2"] == 42

    def test_exception_handling(self) -> None:
        """Test that exceptions are handled properly."""
        tracer: PerformanceTracer | None = None
        with pytest.raises(ValueError):
            with PerformanceTracer("test_operation") as t:
                tracer = t
                raise ValueError("test exception")

        # Duration should still be recorded even with exception
        assert tracer is not None
        assert tracer.duration is not None
        assert tracer.duration > 0

    def test_silent_execution(self) -> None:
        """Test that PerformanceTracer is completely silent during execution."""
        with PerformanceTracer("test_operation") as tracer:
            time.sleep(0.01)

        # Should have recorded duration but not logged anything
        assert tracer.duration is not None
        assert tracer.duration > 0


class TestTraceDecorator:
    """Test the trace decorator."""

    def test_trace_decorator(self) -> None:
        """Test the trace decorator functionality."""
        @trace("decorated_function")
        def test_function() -> str:
            time.sleep(0.01)
            return "success"

        result = test_function()
        assert result == "success"

    def test_trace_decorator_auto_name(self) -> None:
        """Test the trace decorator with auto-detected name."""
        @trace()  # No name provided
        def test_function() -> str:
            time.sleep(0.01)
            return "success"

        result = test_function()
        assert result == "success"

    def test_trace_with_registry_decorator(self) -> None:
        """Test the trace_with_registry decorator."""
        registry = PerformanceRegistry()

        @trace_with_registry("decorated_function", registry=registry)
        def test_function() -> str:
            time.sleep(0.01)
            return "success"

        result = test_function()
        assert result == "success"

        # Check that the trace was recorded after function completion
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        assert "decorated_function" in summary["traces"]

    def test_trace_with_registry_decorator_auto_name(self) -> None:
        """Test the trace_with_registry decorator with auto-detected name."""
        registry = PerformanceRegistry()

        @trace_with_registry(registry=registry)  # No name provided
        def test_function() -> str:
            time.sleep(0.01)
            return "success"

        result = test_function()
        assert result == "success"

        # Check that the trace was recorded with auto-detected name
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        # Should contain the module and function name
        assert "test_function" in list(summary["traces"].keys())[0]


class TestTraceContext:
    """Test the trace context managers."""

    def test_trace_context(self) -> None:
        """Test the trace_context context manager."""
        with trace_context("context_test") as tracer:
            tracer.add_metadata("test_key", "test_value")
            time.sleep(0.01)

        assert tracer.duration is not None
        assert tracer.duration > 0
        assert tracer.metadata["test_key"] == "test_value"

    def test_trace_context_auto_name(self) -> None:
        """Test the trace_context context manager with auto-detected name."""
        with trace_context() as tracer:  # No name provided
            tracer.add_metadata("test_key", "test_value")
            time.sleep(0.01)

        assert tracer.duration is not None
        assert tracer.duration > 0
        assert tracer.metadata["test_key"] == "test_value"
        # Should contain the test function name
        assert "test_trace_context_auto_name" in tracer.name

    def test_trace_context_with_registry(self) -> None:
        """Test the trace_context_with_registry context manager."""
        registry = PerformanceRegistry()

        with trace_context_with_registry("context_test", registry=registry) as tracer:
            tracer.add_metadata("test_key", "test_value")
            time.sleep(0.01)

        assert tracer.duration is not None
        assert tracer.duration > 0

        # Check that the trace was recorded after context exit
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        assert "context_test" in summary["traces"]

    def test_trace_context_with_registry_auto_name(self) -> None:
        """Test the trace_context_with_registry context manager with auto-detected name."""
        registry = PerformanceRegistry()

        with trace_context_with_registry(registry=registry) as tracer:  # No name provided
            tracer.add_metadata("test_key", "test_value")
            time.sleep(0.01)

        assert tracer.duration is not None
        assert tracer.duration > 0

        # Check that the trace was recorded with auto-detected name
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        # Should contain the test function name
        assert "test_trace_context_with_registry_auto_name" in list(summary["traces"].keys())[0]


class TestPerformanceRegistry:
    """Test the PerformanceRegistry class."""

    def test_record_trace(self) -> None:
        """Test recording traces."""
        registry = PerformanceRegistry()
        registry.record_trace("test1", 1.5, {"key1": "value1"})
        registry.record_trace("test2", 2.0, {"key2": "value2"})

        summary = registry.get_summary()
        assert summary["total_traces"] == 2
        assert summary["total_duration"] == 3.5
        assert summary["traces"]["test1"] == 1.5
        assert summary["traces"]["test2"] == 2.0
        assert summary["metadata"]["test1"]["key1"] == "value1"
        assert summary["metadata"]["test2"]["key2"] == "value2"

    def test_empty_registry(self) -> None:
        """Test empty registry behavior."""
        registry = PerformanceRegistry()
        summary = registry.get_summary()

        assert summary["total_traces"] == 0
        assert summary["total_duration"] == 0.0

    def test_clear_registry(self) -> None:
        """Test clearing the registry."""
        registry = PerformanceRegistry()
        registry.record_trace("test1", 1.0)
        registry.clear()

        summary = registry.get_summary()
        assert summary["total_traces"] == 0
        assert summary["total_duration"] == 0.0

    def test_log_summary(self) -> None:
        """Test logging summary."""
        registry = PerformanceRegistry()
        registry.record_trace("test1", 1.0)
        registry.record_trace("test2", 2.0)

        # Test that log_summary doesn't raise an exception
        registry.log_summary()

    def test_log_summary_if_traces(self) -> None:
        """Test log_summary_if_traces behavior."""
        registry = PerformanceRegistry()

        # Should not log when no traces
        registry.log_summary_if_traces()

        # Should log when there are traces
        registry.record_trace("test1", 1.0)
        registry.log_summary_if_traces()

    def test_get_formatted_summary(self) -> None:
        """Test get_formatted_summary."""
        registry = PerformanceRegistry()

        # Test empty registry
        summary = registry.get_formatted_summary()
        assert "No performance traces recorded" in summary

        # Test with traces
        registry.record_trace("test1", 1.0)
        registry.record_trace("test2", 2.0)

        summary = registry.get_formatted_summary()
        assert "Performance Summary" in summary
        assert "test1" in summary
        assert "test2" in summary
        assert "3.000s" in summary  # Total duration


class TestGlobalRegistry:
    """Test the global registry functionality."""

    def test_global_registry_singleton(self) -> None:
        """Test that global registry is a singleton."""
        registry1 = get_global_registry()
        registry2 = get_global_registry()

        assert registry1 is registry2

    def test_global_registry_persistence(self) -> None:
        """Test that global registry persists across calls."""
        registry = get_global_registry()
        registry.clear()  # Start fresh

        @trace_with_registry("global_test")
        def test_function() -> None:
            time.sleep(0.01)

        test_function()

        # Check that the trace was recorded after function completion
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        assert "global_test" in summary["traces"]

    def test_global_registry_auto_name(self) -> None:
        """Test that global registry works with auto-detected names."""
        registry = get_global_registry()
        registry.clear()  # Start fresh

        @trace_with_registry()  # No name provided
        def test_function() -> None:
            time.sleep(0.01)

        test_function()

        # Check that the trace was recorded with auto-detected name
        summary = registry.get_summary()
        assert summary["total_traces"] == 1
        # Should contain the function name
        assert "test_function" in list(summary["traces"].keys())[0]

    def test_log_global_summary(self) -> None:
        """Test log_global_summary function."""
        registry = get_global_registry()
        registry.clear()  # Start fresh

        # Should not log when no traces
        log_global_summary()

        # Should log when there are traces
        registry.record_trace("test1", 1.0)
        log_global_summary()

    def test_get_global_summary(self) -> None:
        """Test get_global_summary function."""
        registry = get_global_registry()
        registry.clear()  # Start fresh

        # Test empty registry
        summary = get_global_summary()
        assert "No performance traces recorded" in summary

        # Test with traces
        registry.record_trace("test1", 1.0)
        summary = get_global_summary()
        assert "Performance Summary" in summary
        assert "test1" in summary

    def test_clear_global_registry(self) -> None:
        """Test clear_global_registry function."""
        registry = get_global_registry()
        registry.record_trace("test1", 1.0)

        clear_global_registry()

        summary = registry.get_summary()
        assert summary["total_traces"] == 0