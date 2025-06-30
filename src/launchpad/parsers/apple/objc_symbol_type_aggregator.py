import re

from dataclasses import dataclass

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ObjCSymbolTypeGroup:
    """Represents a group of symbols with the same class/method."""

    class_name: str
    method_name: str | None
    symbol_count: int
    symbols: list[SymbolSize]

    @property
    def total_size(self) -> int:
        """Calculate the total size of all symbols in this group."""
        return sum(symbol.size for symbol in self.symbols)


class ObjCSymbolTypeAggregator:
    """Aggregates Objective-C symbols by their class/method after parsing."""

    def __init__(self) -> None:
        # Regex pattern to match Objective-C method names: +[ClassName methodName] or -[ClassName methodName]
        self.objc_method_pattern = re.compile(r"(\+|-)\[(\S*)\s(\S*)\]")

    def aggregate_symbols(self, symbol_sizes: list[SymbolSize]) -> list[ObjCSymbolTypeGroup]:
        """
        Group symbols by their class/method and calculate total sizes.
        Only processes Objective-C symbols (excludes those starting with '_$s').

        Args:
            symbol_sizes: List of SymbolSize objects from MachOSymbolSizes

        Returns:
            List of ObjCSymbolTypeGroup objects with aggregated sizes
        """
        # Filter to only Objective-C symbols (exclude Swift and other symbol types)
        objc_symbols: list[SymbolSize] = []
        for symbol in symbol_sizes:
            if symbol.mangled_name.startswith("_$s"):
                # Skip Swift symbols
                continue

            # Check if it's an Objective-C method or metadata symbol
            if self.objc_method_pattern.search(symbol.mangled_name) or symbol.mangled_name.startswith(
                ("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "_OBJC_IVAR_$_")
            ):
                objc_symbols.append(symbol)

        logger.info(f"Found {len(objc_symbols)} Objective-C symbols out of {len(symbol_sizes)} total symbols")

        # Group symbols by class/method
        type_groups: dict[tuple[str, str | None], list[SymbolSize]] = {}

        for symbol in objc_symbols:
            class_name, method_name = self._parse_objc_symbol(symbol.mangled_name)

            key = (class_name, method_name)
            if key not in type_groups:
                type_groups[key] = []
            type_groups[key].append(symbol)

        result: list[ObjCSymbolTypeGroup] = []
        for (class_name, method_name), symbols in type_groups.items():
            result.append(
                ObjCSymbolTypeGroup(
                    class_name=class_name, method_name=method_name, symbol_count=len(symbols), symbols=symbols
                )
            )

        # Sort by total size (descending)
        result.sort(key=lambda x: x.total_size, reverse=True)

        logger.info(f"Aggregated {len(objc_symbols)} Objective-C symbols into {len(result)} type groups")
        return result

    def _parse_objc_symbol(self, mangled_name: str) -> tuple[str, str | None]:
        match = self.objc_method_pattern.search(mangled_name)

        if match:
            # Extract class name and method name from the match
            class_name = match.group(2)
            method_name = match.group(3)

            # Clean up class name - remove category if present
            if "(" in class_name:
                class_name = class_name[: class_name.index("(")]

            # Remove leading underscores
            class_name = class_name.strip("_")

            return class_name, method_name
        else:
            # For symbols that don't match the pattern, try to extract a class name
            # This handles cases like class metadata symbols
            class_name = self._extract_class_name_from_symbol(mangled_name)
            return class_name, None

    def _extract_class_name_from_symbol(self, mangled_name: str) -> str:
        # Remove common prefixes and suffixes
        name = mangled_name

        # Remove common Objective-C prefixes
        prefixes_to_remove = ["_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "_OBJC_IVAR_$_"]
        for prefix in prefixes_to_remove:
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break

        # Remove common suffixes
        suffixes_to_remove = ["_metadata", "_metaclass", "_ivar"]
        for suffix in suffixes_to_remove:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break

        # Clean up the name
        name = name.strip("_")

        # If we still have a reasonable name, return it
        if name and len(name) > 1:
            return name

        return "Unknown"
