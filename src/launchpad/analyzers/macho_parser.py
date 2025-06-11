"""Mach-O binary parser using LIEF."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import lief

from ..models import SwiftMetadata, SymbolInfo
from ..utils.logging import get_logger

logger = get_logger(__name__)


class MachOParser:
    """Parser for Mach-O binaries using LIEF."""

    def __init__(self, binary: lief.Binary) -> None:
        """Initialize the parser with a LIEF binary object."""
        self.binary = binary

    def extract_architectures(self) -> List[str]:
        """Extract CPU architectures from the binary."""
        architectures: list[str] = []

        if hasattr(self.binary, "header") and hasattr(self.binary.header, "cpu_type"):
            # Single architecture binary
            arch = self._cpu_type_to_string(self.binary.header.cpu_type)
            if arch:
                architectures.append(arch)
        elif hasattr(self.binary, "fat_binaries"):
            # Fat binary with multiple architectures
            for fat_binary in self.binary.fat_binaries:
                arch = self._cpu_type_to_string(fat_binary.header.cpu_type)
                if arch:
                    architectures.append(arch)

        return architectures or ["unknown"]

    def extract_linked_libraries(self) -> List[str]:
        """Extract linked dynamic libraries from the binary."""
        libraries: list[str] = []

        if hasattr(self.binary, "libraries"):
            for lib in self.binary.libraries:
                if hasattr(lib, "name"):
                    libraries.append(lib.name)

        return libraries

    def extract_sections(self) -> Dict[str, int]:
        """Extract binary sections and their sizes."""
        sections: dict[str, int] = {}

        if hasattr(self.binary, "sections"):
            for section in self.binary.sections:
                section_name = getattr(section, "name", "unknown")
                section_size = getattr(section, "size", 0)
                sections[section_name] = section_size

        return sections

    def extract_symbols(self, limit: int = 1000) -> List[SymbolInfo]:
        """Extract symbol information from the binary."""
        symbols: List[SymbolInfo] = []

        if not hasattr(self.binary, "symbols"):
            return symbols

        for symbol in self.binary.symbols:
            try:
                symbol_name = getattr(symbol, "name", "unknown")
                symbol_size = getattr(symbol, "size", 0)
                symbol_type = getattr(symbol, "type", "UNDEFINED")

                # Try to determine the section
                section_name = "unknown"
                if hasattr(symbol, "numberof_sections") and symbol.numberof_sections > 0:
                    if hasattr(self.binary, "sections") and len(self.binary.sections) > 0:
                        section_index = min(symbol.numberof_sections - 1, len(self.binary.sections) - 1)
                        section = self.binary.sections[section_index]
                        section_name = getattr(section, "name", "unknown")

                symbols.append(
                    SymbolInfo(
                        name=symbol_name,
                        mangled_name=symbol_name,  # LIEF doesn't demangle automatically
                        size=symbol_size,
                        section=section_name,
                        symbol_type=str(symbol_type),
                    )
                )

            except Exception as e:
                logger.debug(f"Failed to process symbol: {e}")
                continue

        # Sort symbols by size (largest first)
        symbols.sort(key=lambda s: s.size, reverse=True)
        return symbols[:limit]  # Limit to avoid huge outputs

    def extract_swift_metadata(self) -> Optional[SwiftMetadata]:
        """Extract Swift-specific metadata from the binary using comprehensive parser."""
        try:
            # Use the new comprehensive Swift metadata parser
            from .swift_metadata_parser import SwiftMetadataParser

            swift_parser = SwiftMetadataParser(self)
            metadata = swift_parser.parse_swift_metadata()

            if not metadata or metadata["total_metadata_size"] == 0:
                return None

            return SwiftMetadata(
                classes=metadata.get("classes", []),
                protocols=metadata.get("protocols", []),
                extensions=metadata.get("extensions", []),
                total_metadata_size=metadata.get("total_metadata_size", 0),
            )

        except Exception as e:
            logger.debug(f"Failed to extract Swift metadata: {e}")
            return None

    def get_header_size(self) -> int:
        """Get the size of the Mach-O header."""
        # Mach-O header is typically at the beginning
        # Size varies by architecture but 32 bytes is common for 64-bit
        header_size = 32
        if hasattr(self.binary, "header") and hasattr(self.binary.header, "sizeof"):
            header_size = self.binary.header.sizeof
        return header_size

    def get_load_commands(self) -> List[Tuple[int, Any]]:
        """Get load commands with their sizes.

        Returns:
            List of (size, command) tuples
        """
        commands = []
        if hasattr(self.binary, "commands"):
            for command in self.binary.commands:
                cmd_size = getattr(command, "size", 16)  # Default minimum size
                commands.append((cmd_size, command))
        return commands

    def get_sections_with_offsets(self) -> List[Tuple[str, int, int]]:
        """Get sections with their file offsets and sizes.

        Returns:
            List of (name, file_offset, size) tuples
        """
        sections = []
        if hasattr(self.binary, "sections"):
            for section in self.binary.sections:
                section_name = getattr(section, "name", "unknown")
                file_offset = getattr(section, "offset", 0)
                section_size = getattr(section, "size", 0)

                if section_size > 0 and file_offset > 0:
                    sections.append((section_name, file_offset, section_size))

        return sections

    def get_dyld_info(self) -> Optional[Any]:
        """Get DYLD info if available."""
        if hasattr(self.binary, "dyld_info"):
            return self.binary.dyld_info
        return None

    def get_code_signature_info(self) -> Optional[Tuple[int, int]]:
        """Get code signature offset and size if available.

        Returns:
            (offset, size) tuple or None
        """
        if hasattr(self.binary, "code_signature"):
            code_sig = self.binary.code_signature
            if hasattr(code_sig, "data_offset") and hasattr(code_sig, "data_size"):
                return (code_sig.data_offset, code_sig.data_size)
        return None

    def _cpu_type_to_string(self, cpu_type: int) -> Optional[str]:
        """Convert LIEF CPU type to string representation."""
        # Common CPU types from Mach-O
        cpu_types = {
            0x0000000C: "arm",  # ARM
            0x0100000C: "arm64",  # ARM64
            0x00000007: "x86",  # i386
            0x01000007: "x86_64",  # x86_64
        }
        return cpu_types.get(cpu_type)

    def get_section_content(self, section_name: str) -> bytes | None:
        """Get raw bytes content of a specific section.

        Args:
            section_name: Name of the section to retrieve

        Returns:
            Raw bytes of the section content, or None if section not found
        """
        try:
            if not hasattr(self.binary, "sections"):
                return None

            for section in self.binary.sections:
                if hasattr(section, "name") and section.name == section_name:
                    if hasattr(section, "content"):
                        content = section.content
                        return bytes(content)

            logger.debug(f"Section {section_name} not found")
            return None

        except Exception as e:
            logger.debug(f"Failed to get section content for {section_name}: {e}")
            return None

    def get_section_bytes_at_offset(self, section_name: str, offset: int, size: int) -> bytes | None:
        """Get specific bytes from a section at a given offset.

        Args:
            section_name: Name of the section
            offset: Offset within the section
            size: Number of bytes to read

        Returns:
            Raw bytes at the specified offset, or None if not found
        """
        try:
            content = self.get_section_content(section_name)
            if content is None:
                return None

            if offset + size > len(content):
                logger.warning(f"Requested range {offset}:{offset+size} exceeds section size {len(content)}")
                return None

            return content[offset : offset + size]

        except Exception as e:
            logger.debug(f"Failed to get section bytes at offset for {section_name}: {e}")
            return None

    def search_bytes_in_section(self, section_name: str, pattern: bytes) -> list[int]:
        """Search for a byte pattern within a section.

        Args:
            section_name: Name of the section to search in
            pattern: Byte pattern to search for

        Returns:
            List of offsets where the pattern was found
        """
        try:
            content = self.get_section_content(section_name)
            if content is None:
                return []

            offsets = []
            start = 0
            while True:
                pos = content.find(pattern, start)
                if pos == -1:
                    break
                offsets.append(pos)
                start = pos + 1

            return offsets

        except Exception as e:
            logger.debug(f"Failed to search bytes in section {section_name}: {e}")
            return []

    def extract_strings_from_section(self, section_name: str, min_length: int = 4) -> list[tuple[int, str]]:
        """Extract ASCII strings from a section.

        Args:
            section_name: Name of the section (e.g., "__cstring")
            min_length: Minimum string length to consider

        Returns:
            List of (offset, string) tuples
        """
        try:
            content = self.get_section_content(section_name)
            if content is None:
                return []

            strings = []
            current_string = bytearray()
            start_offset = 0

            for i, byte in enumerate(content):
                if 32 <= byte <= 126:  # Printable ASCII
                    if not current_string:
                        start_offset = i
                    current_string.append(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append((start_offset, current_string.decode("ascii")))
                    current_string = bytearray()

            # Handle string at end of section
            if len(current_string) >= min_length:
                strings.append((start_offset, current_string.decode("ascii")))

            return strings

        except Exception as e:
            logger.debug(f"Failed to extract strings from section {section_name}: {e}")
            return []
