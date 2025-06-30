import re

from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ObjCSymbolTypeGroup:
    class_name: str
    method_name: str | None  # None for class-level / ivar symbols
    symbol_count: int
    symbols: List[SymbolSize]

    @property
    def total_size(self) -> int:
        return sum(s.size for s in self.symbols)


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
        "_OBJC_CLASS_$_",
        "_OBJC_METACLASS_$_",
        "_OBJC_IVAR_$_",
        "_OBJC_$_PROP_LIST_",
        "_OBJC_$_CATEGORY_CLASS_",
        "_OBJC_$_CATEGORY_INSTANCE_",
    )

    def aggregate_symbols(self, symbol_sizes: List[SymbolSize]) -> List[ObjCSymbolTypeGroup]:
        buckets: dict[Tuple[str, str | None], list[SymbolSize]] = defaultdict(list)

        for sym in symbol_sizes:
            mname = sym.mangled_name

            # skip swift symbols
            if mname.startswith("_$s"):
                continue

            # method?
            m = self._method_re.search(mname)
            if m:
                class_name = m.group(2).lstrip("_")  # remove any leading _
                selector = m.group(4)
                buckets[(class_name, selector)].append(sym)
                continue

            # objc metadata (class object, metaclass, ivar, etc.)
            if self._is_objc_metadata(mname):
                class_name = self._class_from_metadata(mname)
                buckets[(class_name, None)].append(sym)

        logger.info(
            "Aggregated %d Objective-C symbols into %d groups",
            sum(len(v) for v in buckets.values()),
            len(buckets),
        )

        groups = [
            ObjCSymbolTypeGroup(
                class_name=k[0],
                method_name=k[1],
                symbol_count=len(v),
                symbols=v,
            )
            for k, v in buckets.items()
        ]
        groups.sort(key=lambda g: g.total_size, reverse=True)
        return groups

    @staticmethod
    def _is_objc_metadata(name: str) -> bool:
        return name.startswith(ObjCSymbolTypeAggregator._objc_prefixes)

    @staticmethod
    def _class_from_metadata(name: str) -> str:
        """
        Remove known prefixes and everything after the first dot so that
        `_OBJC_IVAR_$_MyClass._ivarName` becomes `MyClass`.
        """
        for pfx in ObjCSymbolTypeAggregator._objc_prefixes:
            if name.startswith(pfx):
                name = name[len(pfx) :]
                break
        if "." in name:
            name = name.split(".", 1)[0]
        return name.strip("_") or "Unknown"
