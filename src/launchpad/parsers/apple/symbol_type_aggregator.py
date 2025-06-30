from dataclasses import dataclass

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.utils.cwl_demangle import CwlDemangler
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SymbolTypeGroup:
    """Represents a group of symbols with the same module/type."""

    module: str
    type_name: str
    symbol_count: int
    symbols: list[SymbolSize]

    @property
    def total_size(self) -> int:
        """Calculate the total size of all symbols in this group."""
        return sum(symbol.size for symbol in self.symbols)


class SymbolTypeAggregator:
    """Aggregates symbols by their module/type after demangling."""

    def __init__(self) -> None:
        self.demangler = CwlDemangler()

    def aggregate_symbols(self, symbol_sizes: list[SymbolSize]) -> list[SymbolTypeGroup]:
        """
        Group symbols by their module/type and calculate total sizes.

        Args:
            symbol_sizes: List of SymbolSize objects from MachOSymbolSizes

        Returns:
            List of SymbolTypeGroup objects with aggregated sizes
        """
        # Collect all mangled names for batch demangling
        mangled_names = [symbol.mangled_name for symbol in symbol_sizes]

        # Add names to demangler and perform batch demangling
        for name in mangled_names:
            self.demangler.add_name(name)
        demangled_results = self.demangler.demangle_all()

        # Group symbols by module/type
        type_groups: dict[tuple[str, str], list[SymbolSize]] = {}

        for symbol in symbol_sizes:
            demangled_result = demangled_results.get(symbol.mangled_name)

            if demangled_result:
                # Use module and type from demangled result
                module = demangled_result.module or "Unknown"
                type_name = demangled_result.typeName or demangled_result.type or "Unknown"
            else:
                # Fallback for symbols that couldn't be demangled
                module = "Unknown"
                type_name = "Unknown"

            key = (module, type_name)
            if key not in type_groups:
                type_groups[key] = []
            type_groups[key].append(symbol)

        # Convert to SymbolTypeGroup objects
        result: list[SymbolTypeGroup] = []
        for (module, type_name), symbols in type_groups.items():
            result.append(
                SymbolTypeGroup(module=module, type_name=type_name, symbol_count=len(symbols), symbols=symbols)
            )

        # Sort by total size (descending)
        result.sort(key=lambda x: x.total_size, reverse=True)

        logger.info(f"Aggregated {len(symbol_sizes)} symbols into {len(result)} type groups")
        return result
