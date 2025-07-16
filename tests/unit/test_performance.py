"""Basic tests for the performance tracing utilities."""

from __future__ import annotations

import time

from launchpad.utils.performance import Registry, Tracer, trace, trace_ctx


def test_tracer_context_manager() -> None:
    """Test basic Tracer context manager functionality."""
    registry = Registry()

    with Tracer("test_operation", registry=registry) as tracer:
        time.sleep(0.01)

    assert tracer.duration is not None
    assert tracer.duration > 0
    assert tracer.name == "test_operation"
    assert len(registry._samples) == 1  # type: ignore[attr-defined]


def test_tracer_decorator() -> None:
    """Test Tracer decorator functionality."""
    registry = Registry()

    @Tracer.wrap("decorated_function", registry=registry)
    def test_function() -> str:
        time.sleep(0.01)
        return "result"

    result = test_function()

    assert result == "result"
    assert len(registry._samples) == 1  # type: ignore[attr-defined]
    assert registry._samples[0].name == "decorated_function"  # type: ignore[attr-defined]


def test_nested_tracers() -> None:
    """Test parent-child relationships in nested tracers."""
    registry = Registry()

    with Tracer("parent", registry=registry) as parent:
        with Tracer("child", registry=registry) as child:
            time.sleep(0.01)

    assert parent.parent is None
    assert child.parent is parent
    assert len(registry._samples) == 2  # type: ignore[attr-defined]


def test_trace_convenience_decorator() -> None:
    """Test the convenience @trace decorator."""

    @trace("convenience_test")
    def test_function() -> str:
        return "result"

    result = test_function()
    assert result == "result"


def test_trace_ctx_convenience() -> None:
    """Test the convenience trace_ctx context manager."""
    registry = Registry()

    with trace_ctx("context_test", registry=registry):
        time.sleep(0.01)

    assert len(registry._samples) == 1  # type: ignore[attr-defined]
    assert registry._samples[0].name == "context_test"  # type: ignore[attr-defined]


def test_registry_clear() -> None:
    """Test registry clear functionality."""
    registry = Registry()

    with Tracer("test", registry=registry):
        pass

    assert len(registry._samples) == 1  # type: ignore[attr-defined]

    registry.clear()
    assert len(registry._samples) == 0  # type: ignore[attr-defined]
