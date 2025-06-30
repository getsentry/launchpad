from dataclasses import dataclass
from typing import Generator

import lief

from launchpad.utils.cwl_demangle import CwlDemangler
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SymbolSize:
    mangled_name: str
    demangled_name: str
    section: lief.MachO.Section | None
    address: int
    size: int


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


class MachOSymbolSizes:
    """Calculates the size of each symbol in the binary by using the distance-to-next-symbol heuristic."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        self.binary = binary

    def get_symbol_sizes(self) -> list[SymbolSize]:
        """Get the symbol sizes."""
        symbol_tuples = list(self._symbol_sizes(self.binary))
        swift_demangler = CwlDemangler()

        mangled_names = [name for name, _, _, _ in symbol_tuples]
        for name in mangled_names:
            swift_demangler.add_name(name)
        demangled_results = swift_demangler.demangle_all()

        symbol_sizes: list[SymbolSize] = []
        for mangled_name, section, address, size in symbol_tuples:
            demangled_name = demangled_results.get(mangled_name)
            symbol_sizes.append(
                SymbolSize(
                    mangled_name=mangled_name,
                    demangled_name=demangled_name.description if demangled_name else mangled_name,
                    section=section,
                    address=address,
                    size=size,
                )
            )

        logger.info(f"Found {len(symbol_sizes)} symbol sizes")
        return symbol_sizes

    def _is_measurable(self, sym: lief.MachO.Symbol) -> bool:
        """Keep symbols that are actually defined inside a section."""
        return (
            sym.origin == lief.MachO.Symbol.ORIGIN.LC_SYMTAB
            and sym.type == lief.MachO.Symbol.TYPE.SECTION
            and sym.value > 0
        )

    def _symbol_sizes(self, bin: lief.MachO.Binary) -> Generator[tuple[str, lief.MachO.Section | None, int, int]]:
        """Yield (name, addr, size) via the distance-to-next-symbol heuristic."""

        # sort symbols by their address so we can calculate the distance between them
        syms = sorted((s for s in bin.symbols if self._is_measurable(s)), key=lambda s: s.value)

        for idx, sym in enumerate(syms):
            start = sym.value

            section = bin.section_from_virtual_address(start)
            max_section_addr = section.virtual_address + section.size if section else None

            # Only calculate the distance between symbols in the same section
            if max_section_addr:
                if idx + 1 < len(syms):
                    next_sym = syms[idx + 1]
                    next_sym_section = bin.section_from_virtual_address(next_sym.value)
                    end = next_sym.value if next_sym_section.name == section.name else max_section_addr
                else:
                    end = max_section_addr
            else:
                end = syms[idx + 1].value

            yield (str(sym.name), section, start, end - start)
