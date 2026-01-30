from collections.abc import Generator
from dataclasses import dataclass
from typing import NamedTuple

import lief
import sentry_sdk

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def _decode_name(raw_name: str | bytes) -> str:
    """Decode a name from bytes if necessary."""
    return raw_name.decode("utf-8", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)


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
        symbol_sizes = [
            SymbolSize(
                mangled_name=data.name,
                section_name=data.section_name,
                segment_name=data.segment_name,
                address=data.address,
                size=data.size,
            )
            for data in self._symbol_sizes(self.binary)
        ]

        logger.debug(f"Found {len(symbol_sizes)} symbol sizes")
        symbol_sizes.sort(key=lambda x: x.size, reverse=True)
        return symbol_sizes

    def _is_measurable(self, sym: lief.MachO.Symbol) -> bool:
        """Keep symbols that are actually defined inside a section."""
        is_measurable = (
            sym.origin == lief.MachO.Symbol.ORIGIN.SYMTAB
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
        num_syms = len(syms)

        cached_section = None
        cached_section_va = None

        for idx, sym in enumerate(syms):
            start = sym.value

            if cached_section_va == start:
                section = cached_section
            else:
                section = bin.section_from_virtual_address(start)

            if not section:
                logger.warning("size.macho.symbol_not_found_in_section", extra={"symbol": sym.name})
                cached_section = None
                cached_section_va = None
                continue

            max_section_addr = section.virtual_address + section.size
            section_name = _decode_name(section.name)
            segment_name = _decode_name(section.segment.name) if section.segment else None

            if idx + 1 < num_syms:
                next_sym = syms[idx + 1]
                next_sym_section = bin.section_from_virtual_address(next_sym.value)
                cached_section = next_sym_section
                cached_section_va = next_sym.value
                same_section = (
                    next_sym_section
                    and next_sym_section.segment
                    and next_sym_section.segment.name == section.segment.name
                    and next_sym_section.name == section.name
                )
                end = next_sym.value if same_section else max_section_addr
            else:
                end = max_section_addr
                cached_section = None
                cached_section_va = None

            offset_end = bin.virtual_address_to_offset(end)
            offset_start = bin.virtual_address_to_offset(start)
            size = 0
            if not isinstance(offset_end, lief.lief_errors) and not isinstance(offset_start, lief.lief_errors):
                raw_size = offset_end - offset_start
                if raw_size < 0:
                    error_context = {
                        "symbol": sym.name,
                        "offset_start": offset_start,
                        "offset_end": offset_end,
                        "section": section_name,
                    }
                    logger.warning("size.macho.negative_symbol_size", extra=error_context)
                    sentry_sdk.capture_message("size.macho.negative_symbol_size", level="error", extras=error_context)
                size = max(0, raw_size)
            else:
                logger.warning(f"Failed to calculate size for symbol {sym.name}")

            yield _SymbolSizeData(
                name=str(sym.name),
                section_name=section_name,
                segment_name=segment_name,
                address=start,
                size=size,
            )
