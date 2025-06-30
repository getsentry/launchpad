from dataclasses import dataclass

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.utils.cwl_demangle import CwlDemangler
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SwiftSymbolTypeGroup:
    """Represents a group of symbols with the same module/type."""

    module: str
    type_name: str
    symbol_count: int
    symbols: list[SymbolSize]

    @property
    def total_size(self) -> int:
        """Calculate the total size of all symbols in this group."""
        return sum(symbol.size for symbol in self.symbols)


class SwiftSymbolTypeAggregator:
    """Aggregates symbols by their module/type after demangling."""

    def __init__(self) -> None:
        self.demangler = CwlDemangler()

    def aggregate_symbols(self, symbol_sizes: list[SymbolSize]) -> list[SwiftSymbolTypeGroup]:
        """
        Group symbols by their module/type and calculate total sizes.

        Args:
            symbol_sizes: List of SymbolSize objects from MachOSymbolSizes

        Returns:
            List of SymbolTypeGroup objects with aggregated sizes
        """
        mangled_names = [symbol.mangled_name for symbol in symbol_sizes]

        for name in mangled_names:
            self.demangler.add_name(name)
        demangled_results = self.demangler.demangle_all()

        # Group symbols by module/type
        type_groups: dict[tuple[str, str], list[SymbolSize]] = {}

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

            key = (module, type_name)
            if key not in type_groups:
                type_groups[key] = []
            type_groups[key].append(symbol)

        result: list[SwiftSymbolTypeGroup] = []
        for (module, type_name), symbols in type_groups.items():
            result.append(
                SwiftSymbolTypeGroup(module=module, type_name=type_name, symbol_count=len(symbols), symbols=symbols)
            )

        # Sort by total size (descending)
        result.sort(key=lambda x: x.total_size, reverse=True)

        logger.info(f"Aggregated {len(symbol_sizes)} symbols into {len(result)} type groups")
        return result
