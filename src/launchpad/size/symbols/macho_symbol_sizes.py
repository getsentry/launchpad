from collections.abc import Generator
from dataclasses import dataclass
from typing import NamedTuple

import lief

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class _SymbolSizeData(NamedTuple):
    name: str
    section_name: str | None
    segment_name: str | None
    address: int
    size: int


@dataclass
class SymbolSize:
    mangled_name: str
    section_name: str | None
    segment_name: str | None
    address: int
    size: int


class MachOSymbolSizes:
    """Calculates the size of each symbol in the binary by using the distance-to-next-symbol heuristic."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        self.binary = binary

    def get_symbol_sizes(self) -> list[SymbolSize]:
        """Get the symbol sizes."""
        symbol_data = list(self._symbol_sizes(self.binary))

        symbol_sizes: list[SymbolSize] = []
        for data in symbol_data:
            symbol_sizes.append(
                SymbolSize(
                    mangled_name=data.name,
                    section_name=data.section_name,
                    segment_name=data.segment_name,
                    address=data.address,
                    size=data.size,
                )
            )

        logger.debug(f"Found {len(symbol_sizes)} symbol sizes")
        symbol_sizes.sort(key=lambda x: x.size, reverse=True)
        return symbol_sizes

    def _is_measurable(self, sym: lief.MachO.Symbol) -> bool:
        """Keep symbols that are actually defined inside a section."""
        is_measurable = (
            sym.origin == lief.MachO.Symbol.ORIGIN.LC_SYMTAB
            and sym.type == lief.MachO.Symbol.TYPE.SECTION
            and sym.value > 0
        )

        if not is_measurable:
            logger.debug(
                "Symbol marked as not measurable",
                extra={
                    "symbol": sym.name,
                    "origin": str(sym.origin),
                    "type": str(sym.type),
                    "value": sym.value,
                },
            )

        return is_measurable

    def _symbol_sizes(self, bin: lief.MachO.Binary) -> Generator[_SymbolSizeData]:
        """Yield symbol size data via the distance-to-next-symbol heuristic."""

        # sort symbols by their address so we can calculate the distance between them
        syms = sorted((s for s in bin.symbols if self._is_measurable(s)), key=lambda s: s.value)

        for idx, sym in enumerate(syms):
            start = sym.value

            section = bin.section_from_virtual_address(start)
            if section:
                max_section_addr = section.virtual_address + section.size
                raw_name = section.name
                section_name = (
                    raw_name.decode("utf-8", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
                )

                if section.segment:
                    raw_seg_name = section.segment.name
                    segment_name = (
                        raw_seg_name.decode("utf-8", errors="replace")
                        if isinstance(raw_seg_name, bytes)
                        else str(raw_seg_name)
                    )
                else:
                    segment_name = None
            else:
                max_section_addr = None
                section_name = None
                segment_name = None
                logger.warning("size.macho.symbol_not_found_in_section", extra={"symbol": sym.name})
                continue

            # Only calculate the distance between symbols in the same section
            if max_section_addr:
                if idx + 1 < len(syms):
                    next_sym = syms[idx + 1]
                    next_sym_section = bin.section_from_virtual_address(next_sym.value)
                    end = (
                        next_sym.value
                        if next_sym_section and next_sym_section.name == section.name
                        else max_section_addr
                    )
                else:
                    end = max_section_addr
            else:
                end = syms[idx + 1].value

            # Convert virtual addresses to file offsets to calculate the disk size
            offset_end = bin.virtual_address_to_offset(end)
            offset_start = bin.virtual_address_to_offset(start)
            size = 0
            if not isinstance(offset_end, lief.lief_errors) and not isinstance(offset_start, lief.lief_errors):
                size = offset_end - offset_start
            else:
                logger.warning(f"Failed to calculate size for symbol {sym.name}")

            yield _SymbolSizeData(
                name=str(sym.name),
                section_name=section_name,
                segment_name=segment_name,
                address=start,
                size=size,
            )
