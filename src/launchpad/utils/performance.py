"""Tiny performance-tracing helper with hierarchical summaries."""

from __future__ import annotations

import functools
import time

from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, List, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# --------------------------------------------------------------------------- #
# Core tracer                                                                 #
# --------------------------------------------------------------------------- #

_current: ContextVar["Tracer | None"] = ContextVar("_current", default=None)  # type: ignore[assignment]


class Tracer:
    """Context manager / decorator that records wall-clock duration.

    Example
    -------
    >>> with Tracer("outer", registry=REG):
    ...     slow_stuff()
    ...
    >>> @Tracer.wrap(registry=REG)
    ... def f(): ...
    """

    def __init__(self, name: str, *, registry: "Registry | None" = None) -> None:
        self.name = name
        self.registry = registry
        self.parent: "Tracer | None" = None
        self._token = None  # contextvar token
        self._start: float = 0.0
        self.duration: float | None = None
        self.metadata: Dict[str, Any] = {}

    # --------------------------------------------------------------------- #
    # context-manager protocol                                              #
    # --------------------------------------------------------------------- #

    def __enter__(self) -> "Tracer":
        self.parent = _current.get()
        self._token = _current.set(self)
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.duration = time.perf_counter() - self._start
        if self._token is not None:
            _current.reset(self._token)  # restore previous tracer

        # auto-record if a registry was supplied
        if self.registry:
            self.registry.add(self)

    # --------------------------------------------------------------------- #
    # decorator helper                                                      #
    # --------------------------------------------------------------------- #

    @classmethod
    def wrap(
        cls,
        name: str | None = None,
        *,
        registry: "Registry | None" = None,
    ) -> Callable[[F], F]:
        """Decorator equivalent to ``with Tracer(...)``."""

        def decorator(fn: F) -> F:
            trace_name = name or f"{fn.__module__}.{fn.__qualname__}"  # type: ignore[attr-defined]

            @functools.wraps(fn)
            def wrapper(*args: Any, **kw: Any):  # type: ignore[override]
                with cls(trace_name, registry=registry):
                    return fn(*args, **kw)

            return wrapper  # type: ignore[return-value]

        return decorator


# --------------------------------------------------------------------------- #
# Optional registry                                                           #
# --------------------------------------------------------------------------- #


class Registry:
    """Collects Tracer samples and prints a simple tree summary."""

    def __init__(self) -> None:
        self._samples: List[Tracer] = []

    # API used by `Tracer`
    def add(self, tracer: Tracer) -> None:
        self._samples.append(tracer)

    # public helpers --------------------------------------------------------

    def clear(self) -> None:
        self._samples.clear()

    # --------------------------------------------------------------------- #
    # summarisation                                                         #
    # --------------------------------------------------------------------- #

    def _group(self) -> tuple[dict[str, list[float]], dict[str, set[str]], set[str]]:
        """Return durations, child-map, and root set."""
        durs: dict[str, list[float]] = defaultdict(list)
        children: dict[str, set[str]] = defaultdict(set)
        roots: set[str] = set()

        for t in self._samples:
            if t.duration is None:
                continue
            durs[t.name].append(t.duration)
            if t.parent:
                children[t.parent.name].add(t.name)
            else:
                roots.add(t.name)

        return durs, children, roots

    def summary_lines(self) -> list[str]:
        """ASCII tree (no I/O)."""
        if not self._samples:
            return ["No traces recorded."]

        durs, children, roots = self._group()

        def tot(name: str) -> float:
            return sum(durs[name])

        # Only sum the roots to avoid double-counting
        total_time = sum(tot(r) for r in roots)

        lines: list[str] = [
            "=" * 60,
            "HIERARCHICAL PERFORMANCE SUMMARY",
            "=" * 60,
            f"Total duration: {total_time:.3f}s   Traces: {len(durs)}   Executions: {len(self._samples)}",
            "-" * 60,
        ]

        def walk(name: str, prefix: str = "", is_last: bool = True) -> None:
            pct = (tot(name) / total_time) * 100 if total_time else 0
            line = f"{prefix}{'└── ' if is_last else '├── '}{name}: {tot(name):.3f}s ({pct:4.1f} %)"
            cnt = len(durs[name])
            if cnt > 1:
                line += f"  [{cnt}×, avg {tot(name) / cnt:.3f}s]"
            lines.append(line)

            kids = sorted(children.get(name, ()), key=tot, reverse=True)
            for i, child in enumerate(kids):
                extension = "    " if is_last else "│   "
                walk(child, prefix + extension, i == len(kids) - 1)

        for i, root in enumerate(sorted(roots, key=tot, reverse=True)):
            walk(root, "", i == len(roots) - 1)

        lines.append("=" * 60)
        return lines

    # --------------------------------------------------------------------- #
    # public wrappers                                                       #
    # --------------------------------------------------------------------- #

    def summary(self) -> str:  # ← keeps old API
        return "\n".join(self.summary_lines())

    def log_summary(self, logger_name: str | None = None, level: str = "info") -> None:
        """Emit summary through the logger (never prints)."""
        from launchpad.utils.logging import get_logger

        log = get_logger(logger_name) if logger_name else get_logger(__name__)
        log_fn = getattr(log, level, log.info)
        for line in self.summary_lines():
            log_fn(line)


# --------------------------------------------------------------------------- #
# Convenience helpers                                                         #
# --------------------------------------------------------------------------- #

GLOBAL_REGISTRY = Registry()


def trace(name: str | None = None) -> Callable[[F], F]:
    """Decorator that records in the global registry."""
    return Tracer.wrap(name=name, registry=GLOBAL_REGISTRY)


@contextmanager
def trace_ctx(name: str, *, registry: Registry | None = GLOBAL_REGISTRY):
    """Simple ``with`` helper: ``with trace_ctx('step'): ...``."""
    with Tracer(name, registry=registry):
        yield
