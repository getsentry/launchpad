"""Swift protocol conformance parser for Mach-O binaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, List

import lief

from ...utils.logging import get_logger

if TYPE_CHECKING:
    from .macho_parser import MachOParser

logger = get_logger(__name__)


@dataclass
class SwiftProtocolDescriptor:
    """Swift protocol conformance information."""

    protocol_descriptor: int
    conformance_flags: int
    nominal_type_descriptor: int
    protocol_witness_table: int


class SwiftProtocolParser:
    """Parser for Swift protocol conformance information in Mach-O binaries."""

    def __init__(self, binary: lief.MachO.Binary, macho_parser: "MachOParser") -> None:
        """Initialize the parser with a LIEF binary object and reference to main parser."""
        self.binary = binary
        self.macho_parser = macho_parser

    def parse_swift_protocol_conformances(self) -> List[str]:
        """Parse the Swift protocol section."""
        swift_sections = self.macho_parser.extract_swift_sections()
        swift_proto_section = None
        for section in swift_sections:
            if section.name == "__swift5_proto":
                swift_proto_section = section
                break

        if swift_proto_section is None:
            return []

        swift_proto = self.macho_parser.get_section_bytes(str(swift_proto_section.name))
        if swift_proto is None:
            return []

        # The Swift proto section contains a list of offsets to protocol conformance descriptors
        # Each offset is a relative pointer that needs to be added to the base offset
        proto_offsets: List[tuple[int, int]] = []
        for i in range(0, len(swift_proto), 4):
            if i + 4 <= len(swift_proto):
                relative_pointer = int.from_bytes(swift_proto[i : i + 4], byteorder="little", signed=True)
                proto_offsets.append((i + swift_proto_section.offset, relative_pointer))

        protocol_names: List[str] = []
        for base_offset, relative_pointer in proto_offsets:
            type_file_address = relative_pointer + base_offset
            protocol_name = self._parse_swift_protocol_conformance(type_file_address)
            if protocol_name:
                protocol_names.append(protocol_name)

        return protocol_names

    def _parse_swift_protocol_conformance(self, offset: int) -> str | None:
        """Parse a single Swift protocol conformance descriptor."""
        conformance_descriptor = self._parse_swift_protocol_descriptor(offset)
        if conformance_descriptor is None:
            logger.debug(f"Failed to parse protocol descriptor at offset {offset}")
            return None

        protocol_file_offset = self.binary.virtual_address_to_offset(conformance_descriptor.protocol_descriptor)
        uses_chained_fixups = self.binary.has_dyld_chained_fixups
        imported_symbols = self.binary.imported_symbols

        if isinstance(protocol_file_offset, lief.lief_errors) and uses_chained_fixups and len(imported_symbols) > 0:
            ordinal = conformance_descriptor.protocol_descriptor & 0xFFFFFF
            if conformance_descriptor.protocol_descriptor >> 63 == 1 and ordinal < len(imported_symbols):
                protocol_name = imported_symbols[ordinal].name
                return str(protocol_name)
            else:
                logger.debug(f"Failed to parse protocol descriptor at offset {offset}")
                return None

        elif isinstance(protocol_file_offset, lief.lief_errors) and len(imported_symbols) > 0:
            vm_address_result = self.binary.offset_to_virtual_address(offset)
            if isinstance(vm_address_result, lief.lief_errors):
                return None

            vm_address = vm_address_result
            offset_value = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
            if offset_value is None:
                return None

            if offset_value % 2 == 1:
                indirect_vm = vm_address + (offset_value & ~0x1)
                for symbol in self.binary.symbols:
                    if symbol.value == indirect_vm:
                        return str(symbol.name)
                logger.debug("Could not find bound symbol")
                return None
        else:
            if not isinstance(protocol_file_offset, lief.lief_errors):
                logger.debug(
                    f"Protocol descriptor found at offset {protocol_file_offset}, but name extraction not implemented"
                )
                return None

        return None

    def _parse_swift_protocol_descriptor(self, offset: int) -> SwiftProtocolDescriptor | None:
        """Parse a Swift protocol descriptor structure."""
        protocol_descriptor, bytes_read = self.macho_parser.read_indirect_pointer(offset)
        offset += bytes_read

        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        conformance_flags = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if conformance_flags is None:
            logger.debug(f"Failed to read conformance_flags at offset {offset}")
            return None

        offset += 4

        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        nominal_type_descriptor = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if nominal_type_descriptor is None:
            logger.debug(f"Failed to read nominal_type_descriptor at offset {offset}")
            return None

        offset += 4

        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        protocol_witness_table = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if protocol_witness_table is None:
            logger.debug(f"Failed to read protocol_witness_table at offset {offset}")
            return None

        return SwiftProtocolDescriptor(
            protocol_descriptor=protocol_descriptor,
            conformance_flags=conformance_flags,
            nominal_type_descriptor=nominal_type_descriptor,
            protocol_witness_table=protocol_witness_table,
        )
