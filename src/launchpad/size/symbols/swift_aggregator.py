"""Aggregator for Swift symbols by module/type."""

from __future__ import annotations

from typing import NamedTuple

import sentry_sdk

from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.types import SwiftSymbolList, SwiftSymbolTypeGroup
from launchpad.utils.apple.cwl_demangle import CwlDemangler
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class SwiftModuleType(NamedTuple):
    module: str
    type_name: str


class SwiftSymbolTypeAggregator:
    """Aggregates symbols by their module/type after demangling."""

    def __init__(self) -> None:
        self.demangler = CwlDemangler()

    @staticmethod
    def is_swift_symbol(mangled_name: str) -> bool:
        """Check if a symbol is a Swift symbol based on its mangled name.

        Includes:
        - _$s: Modern Swift mangling
        - _Tt: Older Swift mangling
        - __Tt: Swift classes exposed to ObjC with metadata
        """
        if mangled_name.startswith("_$s") or mangled_name.startswith("_Tt") or mangled_name.startswith("__Tt"):
            return True
        return False

    @sentry_sdk.trace
    def aggregate_symbols(self, symbol_sizes: SwiftSymbolList) -> list[SwiftSymbolTypeGroup]:
        # Demangle all Swift symbols
        with sentry_sdk.start_span(op="demangle", description=f"cwl_demangle {len(symbol_sizes)} symbols"):
            for symbol in symbol_sizes:
                self.demangler.add_name(symbol.mangled_name)
            demangled_results = self.demangler.demangle_all()

        # Group symbols by module/type
        with sentry_sdk.start_span(op="aggregate", description=f"group {len(symbol_sizes)} symbols by module/type"):
            type_groups: dict[SwiftModuleType, list[SymbolSize]] = {}

            for symbol in symbol_sizes:
                demangled_result = demangled_results.get(symbol.mangled_name)

                if demangled_result:
                    # Use module and type from demangled result
                    module = demangled_result.module or "Unattributed"
                    type_name = demangled_result.typeName or demangled_result.type or "Unattributed"
                else:
                    # Fallback for symbols that couldn't be demangled
                    module = "Unattributed"
                    type_name = "Unattributed"

                key = SwiftModuleType(module=module, type_name=type_name)
                if key not in type_groups:
                    type_groups[key] = []
                type_groups[key].append(symbol)

            result: list[SwiftSymbolTypeGroup] = []
            for key, symbols in type_groups.items():
                demangled_result = demangled_results.get(symbols[0].mangled_name)
                if demangled_result:
                    components = demangled_result.testName
                else:
                    components = []
                result.append(
                    SwiftSymbolTypeGroup(
                        module=key.module,
                        type_name=key.type_name,
                        components=components,
                        symbol_count=len(symbols),
                        symbols=symbols,
                    )
                )
            result.sort(key=lambda x: x.total_size, reverse=True)

        return result
