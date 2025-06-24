"""Parser for DYLD chained fixups to extract imported symbols."""

from __future__ import annotations

import struct

from typing import List

import lief

from ...utils.logging import get_logger
from .binary_utils import read_null_terminated_string

logger = get_logger(__name__)

LC_REQ_DYLD = 0x80000000
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD

DYLD_CHAINED_IMPORT = 1
DYLD_CHAINED_IMPORT_ADDEND = 2
DYLD_CHAINED_IMPORT_ADDEND64 = 3


class DyldChainedFixupsHeader:
    """Structure for dyld_chained_fixups_header."""

    def __init__(self, data: bytes, offset: int = 0):
        if len(data) < offset + 28:  # 7 * 4 bytes
            raise ValueError("Insufficient data for dyld_chained_fixups_header")

        # Parse 7 UInt32 fields
        fields = struct.unpack("<7I", data[offset : offset + 28])
        self.fixups_version = fields[0]
        self.starts_offset = fields[1]
        self.imports_offset = fields[2]
        self.symbols_offset = fields[3]
        self.imports_count = fields[4]
        self.imports_format = fields[5]
        self.symbols_format = fields[6]


class ChainedFixupsParser:
    """Parser for DYLD chained fixups to extract imported symbols."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        """Initialize the parser with a LIEF binary object."""
        self.binary = binary

    def parse_imported_symbols(self) -> List[str]:
        """Parse the imported symbols from the chained fixups.

        This method parses the LC_DYLD_CHAINED_FIXUPS load command to extract
        imported symbol names from the chained fixups data. The lief version of this
        reports slightly different values which throws off the ordinal parsing.

        Returns:
            List of imported symbol names
        """
        imported_symbols: List[str] = []

        chained_fixups_command = None
        for command in self.binary.commands:
            if command.command == LC_DYLD_CHAINED_FIXUPS:
                if isinstance(command, lief.MachO.DyldChainedFixups):
                    chained_fixups_command = command
                    break

        if not chained_fixups_command:
            logger.error("No LC_DYLD_CHAINED_FIXUPS command found")
            return imported_symbols

        data_offset = chained_fixups_command.data_offset
        data_size = chained_fixups_command.data_size

        vm_address_result = self.binary.offset_to_virtual_address(data_offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.error(f"Failed to convert data offset {data_offset} to virtual address")
            return imported_symbols

        vm_address = vm_address_result

        header_data = self.binary.get_content_from_virtual_address(vm_address, data_size, lief.Binary.VA_TYPES.AUTO)

        if not header_data or len(header_data) < 28:
            logger.error("Insufficient data for chained fixups header")
            return imported_symbols

        header = DyldChainedFixupsHeader(bytes(header_data))

        imports_start_offset = data_offset + header.imports_offset
        symbols_start_offset = data_offset + header.symbols_offset

        imports_size: int
        name_offset_shift: int
        name_offset_mask: int

        if header.imports_format == DYLD_CHAINED_IMPORT:
            imports_size = 4  # UInt32
            name_offset_shift = 9
            name_offset_mask = 0x7FFFFF  # 23 bits
        elif header.imports_format == DYLD_CHAINED_IMPORT_ADDEND:
            imports_size = 8  # UInt32 * 2
            name_offset_shift = 9
            name_offset_mask = 0x7FFFFF  # 23 bits
        elif header.imports_format == DYLD_CHAINED_IMPORT_ADDEND64:
            imports_size = 16  # UInt64 * 2
            name_offset_shift = 32
            name_offset_mask = 0xFFFFFFFF  # 32 bits
        else:
            # Fallback to 32-bit format
            imports_size = 4
            name_offset_shift = 9
            name_offset_mask = 0x7FFFFF
            logger.info("Unknown imports format, will fall back to 32 bit")

        for i in range(header.imports_count):
            import_entry_offset = imports_start_offset + (i * imports_size)

            import_vm_result = self.binary.offset_to_virtual_address(import_entry_offset)
            if isinstance(import_vm_result, lief.lief_errors):
                logger.debug(f"Failed to convert import entry offset {import_entry_offset} to virtual address")
                continue

            import_vm_address = import_vm_result
            import_entry_data = self.binary.get_content_from_virtual_address(
                import_vm_address, imports_size, lief.Binary.VA_TYPES.AUTO
            )

            if not import_entry_data or len(import_entry_data) < 4:
                logger.debug(f"Failed to read import entry {i}")
                continue

            if header.imports_format == DYLD_CHAINED_IMPORT_ADDEND64:
                if len(import_entry_data) >= 8:
                    import_value = int.from_bytes(bytes(import_entry_data[:8]), byteorder="little")
                    name_offset = (import_value >> name_offset_shift) & name_offset_mask
                else:
                    continue
            else:
                import_value = int.from_bytes(bytes(import_entry_data[:4]), byteorder="little")
                name_offset = (import_value >> name_offset_shift) & name_offset_mask

            symbol_name_offset = symbols_start_offset + name_offset
            symbol_name = read_null_terminated_string(self.binary, symbol_name_offset)

            if symbol_name:
                imported_symbols.append(symbol_name)
            else:
                logger.debug(f"Failed to read symbol name at offset {symbol_name_offset}")

        logger.info(f"Found {len(imported_symbols)} imported symbols")

        return imported_symbols
