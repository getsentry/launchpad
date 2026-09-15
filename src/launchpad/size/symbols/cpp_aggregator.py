"""Aggregator for C++ symbols by namespace."""

from __future__ import annotations

from collections import defaultdict
from typing import List, NamedTuple

import sentry_sdk

from launchpad.size.symbols.cpp_demangler import CppDemangler
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

    _demangler = CppDemangler()

    @staticmethod
    def is_cpp_symbol(mangled_name: str) -> bool:
        """Check if a symbol is a C++ symbol based on its mangled name."""
        # C++ symbols often use Itanium mangling: _Z or __Z prefix
        return mangled_name.startswith("_Z") or mangled_name.startswith("__Z")

    @classmethod
    def _extract_namespace_and_function(cls, mangled_name: str) -> CppNamespaceFunction:
        demangled = cls._demangler.demangle(mangled_name)
        if demangled is None:
            return cls._legacy_nested_name(mangled_name)

        for prefix in (
            "construction vtable for ",
            "covariant return thunk to ",
            "guard variable for ",
            "non-virtual thunk to ",
            "typeinfo name for ",
            "typeinfo for ",
            "virtual thunk to ",
            "vtable for ",
            "VTT for ",
        ):
            if demangled.startswith(prefix):
                demangled = demangled[len(prefix) :]
                break

        qualified_name = demangled.split("(", 1)[0]
        if "::" not in qualified_name:
            return CppNamespaceFunction(namespace="(global)", function_name=qualified_name)
        namespace, function_name = qualified_name.rsplit("::", 1)
        return CppNamespaceFunction(namespace=namespace, function_name=function_name)

    @staticmethod
    def _legacy_nested_name(mangled_name: str) -> CppNamespaceFunction:
        if not (mangled_name.startswith("_ZN") or mangled_name.startswith("__ZN")):
            return CppNamespaceFunction(namespace="(global)", function_name=mangled_name)
        encoded = mangled_name[4:] if mangled_name.startswith("__ZN") else mangled_name[3:]
        components: list[str] = []
        index = 0
        while index < len(encoded) and encoded[index].isdigit():
            length_end = index
            while length_end < len(encoded) and encoded[length_end].isdigit():
                length_end += 1
            length = int(encoded[index:length_end])
            component_end = length_end + length
            if component_end > len(encoded):
                break
            components.append(encoded[length_end:component_end])
            index = component_end
        if len(components) < 2:
            return CppNamespaceFunction(
                namespace="(global)", function_name=components[0] if components else mangled_name
            )
        return CppNamespaceFunction(namespace="::".join(components[:-1]), function_name=components[-1])

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
