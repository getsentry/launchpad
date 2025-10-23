"""Aggregator for C++ symbols by namespace."""

from __future__ import annotations

import re

from collections import defaultdict
from typing import List, NamedTuple

import sentry_sdk

from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.types import CppSymbolList, CppSymbolTypeGroup
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class CppNamespaceFunction(NamedTuple):
    namespace: str
    function_name: str


class CppSymbolTypeAggregator:
    """
    Aggregate C++ symbols by namespace and function.
    Groups by (namespace, function_name) buckets.
    """

    # Simplified C++ demangling patterns
    # Full demangling is complex and out of scope for mobile apps
    _cpp_namespace_pattern = re.compile(
        r"__ZN"  # Start of nested name
        r"(?:St)?"  # Optional std:: (St)
        r"(\d+\w+)"  # First namespace/class (length + name)
        r"(?:\d+\w+)*"  # Additional namespaces/classes
    )

    @staticmethod
    def is_cpp_symbol(mangled_name: str) -> bool:
        """Check if a symbol is a C++ symbol based on its mangled name."""
        # C++ symbols often use Itanium mangling: _Z or __Z prefix
        return mangled_name.startswith("_Z") or mangled_name.startswith("__Z")

    @staticmethod
    def _extract_namespace_and_function(mangled_name: str) -> CppNamespaceFunction:
        # Try to extract nested name components
        # Format: __ZN<length><name><length><name>...<length><function>E...
        if not (mangled_name.startswith("_ZN") or mangled_name.startswith("__ZN")):
            # Not a nested name, treat as global namespace
            return CppNamespaceFunction(namespace="(global)", function_name=mangled_name)

        # Skip the __ZN or _ZN prefix
        rest = mangled_name[4:] if mangled_name.startswith("__ZN") else mangled_name[3:]

        # Extract length-prefixed components
        components = []
        i = 0
        while i < len(rest) and rest[i].isdigit():
            # Read the length
            length_str = ""
            while i < len(rest) and rest[i].isdigit():
                length_str += rest[i]
                i += 1

            if not length_str:
                break

            length = int(length_str)
            if i + length > len(rest):
                break

            # Extract the component
            component = rest[i : i + length]
            components.append(component)
            i += length

            # Check if we hit the end marker 'E'
            if i < len(rest) and rest[i] == "E":
                break

        if not components:
            return CppNamespaceFunction(namespace="(unknown)", function_name=mangled_name)

        # Last component is usually the function name
        if len(components) == 1:
            return CppNamespaceFunction(namespace="(global)", function_name=components[0])

        # Build namespace from all but last component
        namespace = "::".join(components[:-1])
        function_name = components[-1]

        # Handle anonymous namespaces
        if "_GLOBAL__N_" in namespace:
            namespace = namespace.replace("_GLOBAL__N_1", "(anonymous)")

        return CppNamespaceFunction(namespace=namespace, function_name=function_name)

    @sentry_sdk.trace
    def aggregate_symbols(self, symbol_sizes: CppSymbolList) -> List[CppSymbolTypeGroup]:
        buckets: dict[CppNamespaceFunction, list[SymbolSize]] = defaultdict(list)

        for sym in symbol_sizes:
            namespace, function_name = self._extract_namespace_and_function(sym.mangled_name)
            key = CppNamespaceFunction(namespace=namespace, function_name=function_name)
            buckets[key].append(sym)

        logger.debug(
            "Aggregated %d C++ symbols into %d groups",
            sum(len(v) for v in buckets.values()),
            len(buckets),
        )

        groups = [
            CppSymbolTypeGroup(
                namespace=key.namespace,
                function_name=key.function_name,
                symbol_count=len(symbols),
                symbols=symbols,
            )
            for key, symbols in buckets.items()
        ]
        groups.sort(key=lambda g: g.total_size, reverse=True)
        return groups
