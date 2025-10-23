"""Aggregator for Objective-C symbols by class/method."""

from __future__ import annotations

import re

from collections import defaultdict
from typing import List, NamedTuple

import sentry_sdk

from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.types import ObjCSymbolList, ObjCSymbolTypeGroup
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ObjCSymbol(NamedTuple):
    class_name: str
    method_name: str | None  # None for class-level / ivar symbols


class ObjCSymbolTypeAggregator:
    """
    Aggregate Objective-C symbols (methods, ivars, class/metaclass objects)
    into (class, method) buckets.  `method_name` is None for class-level items.
    """

    # +[Class(Category) selector:]   -[Class selector:]
    _method_re = re.compile(
        r"([+-])\["  # + or -
        r"(\S+?)"  # class name (non-greedy up to whitespace or '(')
        r"(?:\(([^)\]]+)\))?"  # optional (Category)
        r"\s+([^\]]+)\]"  # selector (may contain :), then ]
    )

    _objc_prefixes = (
        # Single underscore prefixes (external symbols)
        "_OBJC_CLASS_$_",
        "_OBJC_METACLASS_$_",
        "_OBJC_IVAR_$_",
        "_OBJC_$_PROP_LIST_",
        "_OBJC_$_CATEGORY_CLASS_",
        "_OBJC_$_CATEGORY_INSTANCE_",
        # Double underscore prefixes (internal/implementation symbols)
        "__OBJC_CLASS_$_",
        "__OBJC_METACLASS_$_",
        "__OBJC_IVAR_$_",
        "__OBJC_$_PROP_LIST_",
        "__OBJC_$_CATEGORY_CLASS_",
        "__OBJC_$_CATEGORY_INSTANCE_",
        "__OBJC_$_INSTANCE_VARIABLES_",
        "__OBJC_$_INSTANCE_METHODS_",
        "__OBJC_$_CLASS_METHODS_",
        "__OBJC_$_PROTOCOL_INSTANCE_METHODS_",
        "__OBJC_$_PROTOCOL_CLASS_METHODS_",
        "__OBJC_$_PROTOCOL_METHOD_TYPES_",
        "__OBJC_$_CLASS_PROTOCOLS_",
        "__OBJC_$_PROTOCOL_REFS_",
    )

    @classmethod
    def is_objc_symbol(cls, mangled_name: str) -> bool:
        """Check if a symbol is an Objective-C symbol based on its mangled name."""
        # Check for Objective-C method pattern
        if cls._method_re.search(mangled_name):
            return True
        # Check for Objective-C metadata prefixes
        if cls._is_objc_metadata(mangled_name):
            return True
        # Check for Objective-C runtime functions (e.g., _objc_msgSend$function, _objc_retain, etc.)
        if mangled_name.startswith("_objc_") or mangled_name.startswith("__objc_"):
            return True
        return False

    @classmethod
    def _is_objc_metadata(cls, name: str) -> bool:
        """Check if a symbol is Objective-C metadata based on prefixes."""
        return name.startswith(cls._objc_prefixes)

    @classmethod
    def _class_from_metadata(cls, name: str) -> str:
        """
        Remove known prefixes and everything after the first dot so that
        `_OBJC_IVAR_$_MyClass._ivarName` becomes `MyClass`.
        """
        for pfx in cls._objc_prefixes:
            if name.startswith(pfx):
                name = name[len(pfx) :]
                break
        if "." in name:
            name = name.split(".", 1)[0]
        return name.strip("_") or "Unknown"

    @sentry_sdk.trace
    def aggregate_symbols(self, symbol_sizes: ObjCSymbolList) -> List[ObjCSymbolTypeGroup]:
        buckets: dict[ObjCSymbol, list[SymbolSize]] = defaultdict(list)

        for sym in symbol_sizes:
            mname = sym.mangled_name

            # method?
            m = self._method_re.search(mname)
            if m:
                class_name = m.group(2).lstrip("_")  # remove any leading _
                selector = m.group(4)
                key = ObjCSymbol(class_name=class_name, method_name=selector)
                buckets[key].append(sym)
                continue

            # objc metadata (class object, metaclass, ivar, etc.)
            if self._is_objc_metadata(mname):
                class_name = self._class_from_metadata(mname)
                key = ObjCSymbol(class_name=class_name, method_name=None)
                buckets[key].append(sym)
                continue

            # objc runtime functions (_objc_msgSend, _objc_retain, etc.)
            if mname.startswith("_objc_") or mname.startswith("__objc_"):
                # Group all runtime functions under "ObjC Runtime"
                key = ObjCSymbol(class_name="ObjC Runtime", method_name=None)
                buckets[key].append(sym)

        logger.debug(
            "Aggregated %d Objective-C symbols into %d groups",
            sum(len(v) for v in buckets.values()),
            len(buckets),
        )

        groups = [
            ObjCSymbolTypeGroup(
                class_name=key.class_name,
                method_name=key.method_name,
                symbol_count=len(symbols),
                symbols=symbols,
            )
            for key, symbols in buckets.items()
        ]
        groups.sort(key=lambda g: g.total_size, reverse=True)
        return groups
