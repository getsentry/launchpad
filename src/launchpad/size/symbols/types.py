"""Data types for symbol aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize


class SwiftSymbolList(list[SymbolSize]):
    """Type-safe wrapper for Swift symbols."""

    pass


class ObjCSymbolList(list[SymbolSize]):
    """Type-safe wrapper for Objective-C symbols."""

    pass


class CppSymbolList(list[SymbolSize]):
    """Type-safe wrapper for C++ symbols."""

    pass


@dataclass
class SwiftSymbolTypeGroup:
    """Represents a group of symbols with the same module/type."""

    # E.g. HackerNews
    module: str
    # E.g. AppViewModel
    type_name: str
    # E.g. ['HackerNews', 'AppViewModel']
    components: List[str]
    symbol_count: int
    symbols: list[SymbolSize]

    @property
    def total_size(self) -> int:
        """Calculate the total size of all symbols in this group."""
        return sum(symbol.size for symbol in self.symbols)


@dataclass
class ObjCSymbolTypeGroup:
    """Represents a group of Objective-C symbols by class/method."""

    class_name: str
    method_name: str | None  # None for class-level / ivar symbols
    symbol_count: int
    symbols: List[SymbolSize]

    @property
    def total_size(self) -> int:
        return sum(s.size for s in self.symbols)


@dataclass
class CppSymbolTypeGroup:
    """Represents a group of C++ symbols in the same namespace."""

    namespace: str  # e.g., "sentry::profiling"
    function_name: str | None  # None for namespace-level symbols
    symbol_count: int
    symbols: List[SymbolSize]

    @property
    def total_size(self) -> int:
        return sum(s.size for s in self.symbols)
