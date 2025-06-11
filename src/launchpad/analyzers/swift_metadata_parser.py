"""Swift metadata parser for iOS binaries."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import BinaryTag
from ..models.range_mapping import RangeMap
from ..utils.logging import get_logger
from .macho_parser import MachOParser

logger = get_logger(__name__)


class ContextDescriptorKind(IntEnum):
    """Swift context descriptor kinds."""

    MODULE = 0
    EXTENSION = 1
    ANONYMOUS = 2
    PROTOCOL = 3
    OPAQUE_TYPE = 4
    CLASS = 16
    STRUCT = 17
    ENUM = 18


class TypeContextDescriptorFlags(IntEnum):
    """Flags for Swift type context descriptors."""

    HAS_VTABLE = 0x8000
    HAS_RESILIENT_SUPERCLASS = 0x2000
    HAS_FOREIGN_METADATA_INITIALIZATION = 0x0200
    HAS_SINGLETON_METADATA_INITIALIZATION = 0x0100
    HAS_CANONICAL_METADATA_PRESPECIALIZATIONS = 0x0040


@dataclass
class SwiftTypeDetails:
    """Details about a Swift type found in metadata."""

    module_name: str
    type_path: List[str]
    kind: ContextDescriptorKind
    size: int = 0

    @property
    def full_name(self) -> str:
        """Get the full qualified name of the type."""
        return ".".join([self.module_name] + self.type_path)

    def child_type(self, name: str) -> SwiftTypeDetails:
        """Create a child type under this type."""
        return SwiftTypeDetails(
            module_name=self.module_name,
            type_path=self.type_path + [name],
            kind=ContextDescriptorKind.CLASS,  # Default, will be updated
        )


@dataclass
class SwiftMetadataSection:
    """Information about a Swift metadata section."""

    name: str
    content: bytes
    file_offset: int
    size: int


class SwiftMetadataParser:
    """Parser for Swift metadata sections in iOS binaries."""

    def __init__(self, parser: MachOParser, range_map: Optional[RangeMap] = None) -> None:
        """Initialize the Swift metadata parser.

        Args:
            parser: MachO parser instance
            range_map: Optional range map for tracking byte attribution
        """
        self.parser = parser
        self.range_map = range_map
        self.parsed_types: Dict[int, SwiftTypeDetails] = {}
        self.swift_modules: Set[str] = set()
        self.swift_classes: List[str] = []
        self.swift_protocols: List[str] = []
        self.swift_extensions: List[str] = []

    def parse_swift_metadata(self) -> Dict[str, Any]:
        """Parse all Swift metadata from the binary.

        Returns:
            Dictionary containing parsed Swift metadata
        """
        logger.debug("Starting Swift metadata parsing")

        # Parse different Swift metadata sections
        self._parse_swift_types()
        self._parse_swift_protocols()
        self._parse_swift_protocol_conformances()

        total_metadata_size = self._calculate_total_metadata_size()

        logger.info(
            f"Parsed Swift metadata: {len(self.swift_modules)} modules, "
            f"{len(self.swift_classes)} classes, {len(self.swift_protocols)} protocols"
        )

        return {
            "classes": self.swift_classes,
            "protocols": self.swift_protocols,
            "extensions": self.swift_extensions,
            "modules": list(self.swift_modules),
            "total_metadata_size": total_metadata_size,
        }

    def _parse_swift_types(self) -> None:
        """Parse Swift type descriptors from __swift5_types section."""
        types_content = self.parser.get_section_content("__swift5_types")
        if not types_content:
            logger.debug("No __swift5_types section found")
            return

        logger.debug(f"Parsing __swift5_types section ({len(types_content)} bytes)")

        # Each entry in __swift5_types is a 32-bit relative offset
        num_entries = len(types_content) // 4

        for i in range(num_entries):
            try:
                # Read 32-bit relative offset
                offset_data = types_content[i * 4 : (i + 1) * 4]
                if len(offset_data) != 4:
                    continue

                relative_offset = struct.unpack("<i", offset_data)[0]

                # Handle indirect pointers (least significant bit set)
                if relative_offset & 1:
                    # Indirect pointer - need to follow the reference
                    # This is more complex and would require VM address resolution
                    logger.debug(f"Skipping indirect type pointer at entry {i}")
                    continue

                # Calculate absolute offset within the section
                type_offset = (i * 4) + relative_offset

                if type_offset < 0 or type_offset >= len(types_content):
                    logger.debug(f"Invalid type offset {type_offset} for entry {i}")
                    continue

                # Parse the type descriptor at this offset
                self._parse_type_descriptor(types_content, type_offset, i * 4)

            except Exception as e:
                logger.debug(f"Failed to parse type entry {i}: {e}")
                continue

    def _parse_type_descriptor(
        self, section_content: bytes, offset: int, pointer_offset: int
    ) -> Optional[SwiftTypeDetails]:
        """Parse a Swift type descriptor at the given offset.

        Args:
            section_content: Raw bytes of the section
            offset: Offset within the section
            pointer_offset: Offset of the pointer that led to this descriptor

        Returns:
            Parsed type details or None if parsing failed
        """
        try:
            if offset + 16 > len(section_content):  # Need at least 16 bytes for basic descriptor
                return None

            # Read the context descriptor header
            flags_data = section_content[offset : offset + 4]
            parent_data = section_content[offset + 4 : offset + 8]
            name_data = section_content[offset + 8 : offset + 12]

            flags = struct.unpack("<I", flags_data)[0]
            parent_offset = struct.unpack("<i", parent_data)[0]
            name_offset = struct.unpack("<i", name_data)[0]

            # Extract kind from flags
            kind = ContextDescriptorKind(flags & 0x1F)

            # Get the type name
            name_abs_offset = (offset + 8) + name_offset
            type_name = self._read_null_terminated_string(section_content, name_abs_offset)

            if not type_name:
                return None

            # Resolve parent context
            parent_type = None
            if parent_offset != 0:
                parent_abs_offset = (offset + 4) + parent_offset
                parent_type = self._parse_type_descriptor(section_content, parent_abs_offset, -1)

            # Create type details
            if parent_type:
                type_details = parent_type.child_type(type_name)
                type_details.kind = kind
            else:
                # This is a module descriptor
                type_details = SwiftTypeDetails(module_name=type_name, type_path=[], kind=kind)
                self.swift_modules.add(type_name)

            # Store in parsed types cache
            self.parsed_types[pointer_offset] = type_details

            # Add to appropriate collections
            self._categorize_type(type_details)

            # Parse type-specific trailing data
            trailing_size = self._parse_type_specific_data(section_content, offset, kind, type_details)

            # Add range mapping if available
            if self.range_map:
                base_size = 16  # Basic descriptor size
                total_size = base_size + trailing_size

                # Map the descriptor itself
                self.range_map.add_range(
                    pointer_offset,
                    pointer_offset + 4,
                    BinaryTag.SWIFT_METADATA,
                    f"swift_type_pointer_{type_details.full_name}",
                )

                # Map the type name
                name_size = len(type_name.encode("utf-8")) + 1  # Include null terminator
                self.range_map.add_range(
                    name_abs_offset,
                    name_abs_offset + name_size,
                    BinaryTag.SWIFT_METADATA,
                    f"swift_type_name_{type_details.full_name}",
                )

                # Map the descriptor structure
                self.range_map.add_range(
                    offset,
                    offset + total_size,
                    BinaryTag.SWIFT_METADATA,
                    f"swift_type_descriptor_{type_details.full_name}",
                )

            return type_details

        except Exception as e:
            logger.debug(f"Failed to parse type descriptor at offset {offset}: {e}")
            return None

    def _parse_type_specific_data(
        self,
        section_content: bytes,
        offset: int,
        kind: ContextDescriptorKind,
        type_details: SwiftTypeDetails,
    ) -> int:
        """Parse type-specific trailing data and return the size consumed.

        Args:
            section_content: Raw bytes of the section
            offset: Current offset in the section
            kind: Type of descriptor
            type_details: Type details being parsed

        Returns:
            Number of bytes consumed by trailing data
        """
        trailing_size = 0

        try:
            if kind == ContextDescriptorKind.CLASS:
                trailing_size = self._parse_class_trailing_data(section_content, offset + 16, type_details)
            elif kind == ContextDescriptorKind.STRUCT:
                trailing_size = self._parse_struct_trailing_data(section_content, offset + 16, type_details)
            elif kind == ContextDescriptorKind.ENUM:
                trailing_size = self._parse_enum_trailing_data(section_content, offset + 16, type_details)
            elif kind == ContextDescriptorKind.PROTOCOL:
                trailing_size = self._parse_protocol_trailing_data(section_content, offset + 16, type_details)

        except Exception as e:
            logger.debug(f"Failed to parse trailing data for {kind}: {e}")

        return trailing_size

    def _parse_class_trailing_data(self, section_content: bytes, offset: int, type_details: SwiftTypeDetails) -> int:
        """Parse class-specific trailing data."""
        consumed = 0

        try:
            if offset + 16 > len(section_content):
                return 0

            # Read class-specific fields (but don't store unused ones)
            struct.unpack("<i", section_content[offset : offset + 4])[0]  # superclass_type_offset

            consumed += 16

            # Check for generic parameters and requirements
            if offset + 16 < len(section_content):
                # Read flags to determine what trailing objects exist
                flags_data = section_content[offset - 16 : offset - 12]
                flags = struct.unpack("<I", flags_data)[0]

                # Generic context handling would go here
                if flags & 0x80:  # Has generic signature
                    logger.debug(f"Class {type_details.full_name} has generic signature")
                    # Would parse generic parameters and requirements

                # VTable handling
                if flags & TypeContextDescriptorFlags.HAS_VTABLE:
                    vtable_size = self._parse_vtable_descriptor(section_content, offset + consumed, type_details)
                    consumed += vtable_size

        except Exception as e:
            logger.debug(f"Failed to parse class trailing data: {e}")

        return consumed

    def _parse_struct_trailing_data(self, section_content: bytes, offset: int, type_details: SwiftTypeDetails) -> int:
        """Parse struct-specific trailing data."""
        consumed = 0

        try:
            if offset + 12 > len(section_content):
                return 0

            # Skip struct-specific fields for now
            consumed += 12

            # Generic context handling would go here

        except Exception as e:
            logger.debug(f"Failed to parse struct trailing data: {e}")

        return consumed

    def _parse_enum_trailing_data(self, section_content: bytes, offset: int, type_details: SwiftTypeDetails) -> int:
        """Parse enum-specific trailing data."""
        consumed = 0

        try:
            if offset + 12 > len(section_content):
                return 0

            # Skip enum-specific fields for now
            consumed += 12

        except Exception as e:
            logger.debug(f"Failed to parse enum trailing data: {e}")

        return consumed

    def _parse_protocol_trailing_data(self, section_content: bytes, offset: int, type_details: SwiftTypeDetails) -> int:
        """Parse protocol-specific trailing data."""
        consumed = 0

        try:
            if offset + 16 > len(section_content):
                return 0

            # Skip protocol-specific fields for now and just read num_requirements
            num_requirements = struct.unpack("<I", section_content[offset + 8 : offset + 12])[0]

            consumed += 16

            # Requirements would be parsed here (each is typically 12 bytes)
            requirements_size = min(num_requirements * 12, len(section_content) - offset - consumed)
            consumed += requirements_size

        except Exception as e:
            logger.debug(f"Failed to parse protocol trailing data: {e}")

        return consumed

    def _parse_vtable_descriptor(self, section_content: bytes, offset: int, type_details: SwiftTypeDetails) -> int:
        """Parse VTable descriptor for a class."""
        try:
            if offset + 8 > len(section_content):
                return 0

            # Read VTable size
            vtable_size = struct.unpack("<I", section_content[offset + 4 : offset + 8])[0]

            logger.debug(f"Class {type_details.full_name} has VTable with {vtable_size} entries")

            # Each VTable entry is typically 8 bytes (implementation + flags)
            return 8 + (int(vtable_size) * 8)

        except Exception as e:
            logger.debug(f"Failed to parse VTable descriptor: {e}")
            return 0

    def _parse_swift_protocols(self) -> None:
        """Parse Swift protocol descriptors from __swift5_protos section."""
        protos_content = self.parser.get_section_content("__swift5_protos")
        if not protos_content:
            logger.debug("No __swift5_protos section found")
            return

        logger.debug(f"Parsing __swift5_protos section ({len(protos_content)} bytes)")

        # Similar to types, each entry is a 32-bit relative offset
        num_entries = len(protos_content) // 4

        for i in range(num_entries):
            try:
                offset_data = protos_content[i * 4 : (i + 1) * 4]
                if len(offset_data) != 4:
                    continue

                relative_offset = struct.unpack("<i", offset_data)[0]

                if relative_offset & 1:
                    logger.debug(f"Skipping indirect protocol pointer at entry {i}")
                    continue

                protocol_offset = (i * 4) + relative_offset

                if protocol_offset < 0 or protocol_offset >= len(protos_content):
                    continue

                # Parse protocol descriptor
                type_details = self._parse_type_descriptor(protos_content, protocol_offset, i * 4)
                if type_details and type_details.kind == ContextDescriptorKind.PROTOCOL:
                    self.swift_protocols.append(type_details.full_name)

            except Exception as e:
                logger.debug(f"Failed to parse protocol entry {i}: {e}")
                continue

    def _parse_swift_protocol_conformances(self) -> None:
        """Parse Swift protocol conformances from __swift5_proto section."""
        conformances_content = self.parser.get_section_content("__swift5_proto")
        if not conformances_content:
            logger.debug("No __swift5_proto section found")
            return

        logger.debug(f"Parsing __swift5_proto section ({len(conformances_content)} bytes)")

        # Each conformance descriptor is variable size, need to parse sequentially
        offset = 0
        conformance_count = 0

        while offset + 16 <= len(conformances_content):  # Minimum conformance descriptor size
            try:
                # Parse conformance descriptor
                protocol_descriptor_data = conformances_content[offset : offset + 4]
                nominal_type_descriptor_data = conformances_content[offset + 4 : offset + 8]
                protocol_witness_table_data = conformances_content[offset + 8 : offset + 12]
                conformance_flags_data = conformances_content[offset + 12 : offset + 16]

                conformance_flags = struct.unpack("<I", conformance_flags_data)[0]

                # Add range mapping for conformance descriptor
                if self.range_map:
                    self.range_map.add_range(
                        offset,
                        offset + 16,
                        BinaryTag.SWIFT_METADATA,
                        f"swift_protocol_conformance_{conformance_count}",
                    )

                offset += 16
                conformance_count += 1

                # Skip trailing objects based on flags
                # This is simplified - real implementation would parse the trailing objects
                if conformance_flags & 0x01:  # Has generic witness table
                    offset += 8  # Skip generic witness table

            except Exception as e:
                logger.debug(f"Failed to parse conformance at offset {offset}: {e}")
                offset += 16  # Skip to next potential conformance
                continue

        logger.debug(f"Parsed {conformance_count} protocol conformances")

    def _categorize_type(self, type_details: SwiftTypeDetails) -> None:
        """Categorize a parsed type into the appropriate collection."""
        if type_details.kind == ContextDescriptorKind.CLASS:
            self.swift_classes.append(type_details.full_name)
        elif type_details.kind == ContextDescriptorKind.PROTOCOL:
            self.swift_protocols.append(type_details.full_name)
        elif type_details.kind == ContextDescriptorKind.EXTENSION:
            self.swift_extensions.append(type_details.full_name)

    def _read_null_terminated_string(self, data: bytes, offset: int) -> Optional[str]:
        """Read a null-terminated string from the given offset."""
        try:
            if offset < 0 or offset >= len(data):
                return None

            end_offset = offset
            while end_offset < len(data) and data[end_offset] != 0:
                end_offset += 1

            if end_offset >= len(data):
                return None

            return data[offset:end_offset].decode("utf-8", errors="ignore")

        except Exception as e:
            logger.debug(f"Failed to read string at offset {offset}: {e}")
            return None

    def _calculate_total_metadata_size(self) -> int:
        """Calculate the total size of Swift metadata sections."""
        total_size = 0

        swift_sections = [
            "__swift5_types",
            "__swift5_protos",
            "__swift5_proto",
            "__swift5_typeref",
            "__swift5_reflstr",
            "__swift5_fieldmd",
            "__swift5_assocty",
            "__swift5_replace",
            "__swift5_replac2",
        ]

        for section_name in swift_sections:
            content = self.parser.get_section_content(section_name)
            if content:
                total_size += len(content)
                logger.debug(f"Section {section_name}: {len(content)} bytes")

        return total_size
