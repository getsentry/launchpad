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
        architectures = []

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
        libraries = []

        if hasattr(self.binary, "libraries"):
            for lib in self.binary.libraries:
                if hasattr(lib, "name"):
                    libraries.append(lib.name)

        return libraries

    def extract_sections(self) -> Dict[str, int]:
        """Extract binary sections and their sizes."""
        sections = {}

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
        """Extract Swift-specific metadata from the binary.

        This is a simplified implementation. A full implementation would
        parse Swift metadata sections more thoroughly.
        """
        try:
            # Look for Swift-related sections
            swift_sections = []
            if hasattr(self.binary, "sections"):
                for section in self.binary.sections:
                    section_name = getattr(section, "name", "")
                    if "swift" in section_name.lower():
                        swift_sections.append(section)

            if not swift_sections:
                return None

            # Calculate total Swift metadata size
            total_metadata_size = sum(getattr(section, "size", 0) for section in swift_sections)

            # For now, return basic metadata
            # In a full implementation, you would parse the actual Swift metadata structures
            return SwiftMetadata(
                classes=[],  # Would be extracted from __swift5_types section
                protocols=[],  # Would be extracted from __swift5_protos section
                extensions=[],  # Would be extracted from various Swift sections
                total_metadata_size=total_metadata_size,
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
