"""Symbol partitioner that categorizes and aggregates symbols by language."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, List, NamedTuple

import sentry_sdk

from launchpad.size.symbols.cpp_aggregator import CppSymbolTypeAggregator
from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.objc_aggregator import ObjCSymbolTypeAggregator
from launchpad.size.symbols.swift_aggregator import SwiftSymbolTypeAggregator
from launchpad.size.symbols.types import (
    CppSymbolList,
    CppSymbolTypeGroup,
    ObjCSymbolList,
    ObjCSymbolTypeGroup,
    SwiftSymbolList,
    SwiftSymbolTypeGroup,
)
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class SectionSymbol(NamedTuple):
    """Symbol information for section grouping."""

    module: str
    name: str
    address: int
    size: int


@dataclass
class SymbolInfo:
    """Symbol information with explicit partitioning.

    Symbols are partitioned into five mutually exclusive groups:
    - swift_type_groups: Swift symbols aggregated by module/type
    - objc_type_groups: Objective-C symbols aggregated by class/method
    - cpp_type_groups: C++ symbols aggregated by namespace/function
    - other_symbols: Everything else (C functions, etc.)
    - compiler_generated_symbols: Compiler-generated symbols (outlined functions, helpers, etc.)

    This ensures every symbol is accounted for exactly once.
    """

    symbol_sizes: List[SymbolSize]  # All symbols (for reference)
    swift_type_groups: List[SwiftSymbolTypeGroup]
    objc_type_groups: List[ObjCSymbolTypeGroup]
    cpp_type_groups: List[CppSymbolTypeGroup]
    other_symbols: List[SymbolSize]  # Symbols not in Swift/ObjC/C++ groups
    compiler_generated_symbols: List[SymbolSize]  # Compiler-generated symbols

    @staticmethod
    def _is_compiler_generated(mangled_name: str) -> bool:
        """Check if a symbol is compiler-generated and should be excluded from attribution.

        These symbols are typically:
        - Compiler optimization artifacts (outlined functions)
        - Runtime helpers (blocks, copy/destroy helpers)
        - Global initializers
        - Internal runtime symbols
        """
        # Compiler outlining optimization
        if mangled_name.startswith("_OUTLINED_FUNCTION"):
            return True
        # Global initializers
        if mangled_name.startswith("_globalinit_"):
            return True
        # Objective-C blocks
        if mangled_name.startswith("_block_") or mangled_name.startswith("___Block_"):
            return True
        # Copy/destroy helpers
        if mangled_name.startswith("___copy_") or mangled_name.startswith("___destroy"):
            return True
        # Swift runtime internals
        if mangled_name.startswith("___swift_"):
            return True
        # Object destruction helpers
        if mangled_name.startswith("_objectdestroy."):
            return True
        return False

    @classmethod
    @sentry_sdk.trace
    def from_symbol_sizes(cls, symbol_sizes: List[SymbolSize]) -> "SymbolInfo":
        with sentry_sdk.start_span(op="partition_symbols", description="Partition symbols by language"):
            swift_symbols = SwiftSymbolList()
            objc_symbols = ObjCSymbolList()
            cpp_symbols = CppSymbolList()
            other_symbols: List[SymbolSize] = []
            compiler_generated_symbols: List[SymbolSize] = []

            for symbol in symbol_sizes:
                if cls._is_compiler_generated(symbol.mangled_name):
                    compiler_generated_symbols.append(symbol)
                elif SwiftSymbolTypeAggregator.is_swift_symbol(symbol.mangled_name):
                    swift_symbols.append(symbol)
                elif ObjCSymbolTypeAggregator.is_objc_symbol(symbol.mangled_name):
                    objc_symbols.append(symbol)
                elif CppSymbolTypeAggregator.is_cpp_symbol(symbol.mangled_name):
                    cpp_symbols.append(symbol)
                else:
                    other_symbols.append(symbol)

        # Aggregate each partition
        swift_type_groups = SwiftSymbolTypeAggregator().aggregate_symbols(swift_symbols)
        objc_type_groups = ObjCSymbolTypeAggregator().aggregate_symbols(objc_symbols)
        cpp_type_groups = CppSymbolTypeAggregator().aggregate_symbols(cpp_symbols)

        logger.debug(
            f"Partitioned {len(symbol_sizes)} symbols: "
            f"Swift={len(swift_symbols)}, ObjC={len(objc_symbols)}, C++={len(cpp_symbols)}, "
            f"Other={len(other_symbols)}, Compiler-generated={len(compiler_generated_symbols)}"
        )

        return cls(
            symbol_sizes=symbol_sizes,
            swift_type_groups=swift_type_groups,
            objc_type_groups=objc_type_groups,
            cpp_type_groups=cpp_type_groups,
            other_symbols=other_symbols,
            compiler_generated_symbols=compiler_generated_symbols,
        )

    def get_symbols_by_section(self) -> dict[str, list[SectionSymbol]]:
        symbols_by_section: dict[str, list[SectionSymbol]] = defaultdict(list)

        def add_group_symbols(
            groups: List[SwiftSymbolTypeGroup | ObjCSymbolTypeGroup | CppSymbolTypeGroup],
            get_identifiers: Callable[
                [SwiftSymbolTypeGroup | ObjCSymbolTypeGroup | CppSymbolTypeGroup], tuple[str, str]
            ],
        ) -> None:
            for group in groups:
                module, name = get_identifiers(group)
                for symbol in group.symbols:
                    section_name = symbol.section_name or "unknown"
                    symbols_by_section[section_name].append(
                        SectionSymbol(module=module, name=name, address=symbol.address, size=symbol.size)
                    )

        add_group_symbols(self.swift_type_groups, lambda g: (g.module, g.type_name))
        add_group_symbols(self.objc_type_groups, lambda g: (g.class_name, g.method_name or "class"))
        add_group_symbols(self.cpp_type_groups, lambda g: (g.namespace, g.function_name or "namespace"))

        for symbol in self.other_symbols:
            section_name = symbol.section_name or "unknown"
            symbols_by_section[section_name].append(
                SectionSymbol(module="Other", name=symbol.mangled_name, address=symbol.address, size=symbol.size)
            )

        return symbols_by_section
