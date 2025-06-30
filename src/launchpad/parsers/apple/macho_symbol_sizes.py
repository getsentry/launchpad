from collections.abc import Generator
from dataclasses import dataclass

import lief

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SymbolSize:
    mangled_name: str
    section: lief.MachO.Section | None
    address: int
    size: int


class MachOSymbolSizes:
    """Calculates the size of each symbol in the binary by using the distance-to-next-symbol heuristic."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        self.binary = binary

    def get_symbol_sizes(self) -> list[SymbolSize]:
        """Get the symbol sizes."""
        symbol_tuples = list(self._symbol_sizes(self.binary))

        symbol_sizes: list[SymbolSize] = []
        for mangled_name, section, address, size in symbol_tuples:
            symbol_sizes.append(
                SymbolSize(
                    mangled_name=mangled_name,
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
