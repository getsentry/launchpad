"""Mach-O binary parser using LIEF."""

from __future__ import annotations

from typing import Dict, List

import lief

from ...utils.logging import get_logger

logger = get_logger(__name__)


class MachOParser:
    """Parser for Mach-O binaries using LIEF."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        """Initialize the parser with a LIEF binary object."""
        self.binary = binary

    def extract_architectures(self) -> List[str]:
        """Extract CPU architectures from the binary."""
        return [str(self.binary.header.cpu_type)]

    def extract_linked_libraries(self) -> List[str]:
        """Extract linked dynamic libraries from the binary."""
        return [str(lib.name) for lib in self.binary.libraries]

    def extract_sections(self) -> Dict[str, int]:
        """Extract binary sections and their sizes."""
        return {str(section.name): section.size for section in self.binary.sections}

    def extract_swift_sections(self) -> List[lief.Section]:
        """Get Swift sections from the binary."""
        return [section for section in self.binary.sections if "swift" in str(section.name).lower()]

    def get_header_size(self) -> int:
        """Get the size of the Mach-O header."""
        # Mach-O header is typically at the beginning
        # Size varies by architecture but 32 bytes is common for 64-bit
        header_size = 32
        # TODO: implement proper header size, seems hard to do with LIEF
        return header_size

    def _cpu_type_to_string(self, cpu_type: int) -> str | None:
        """Convert LIEF CPU type to string representation."""
        # Common CPU types from Mach-O
        cpu_types = {
            0x0000000C: "arm",  # ARM
            0x0100000C: "arm64",  # ARM64
            0x00000007: "x86",  # i386
            0x01000007: "x86_64",  # x86_64
        }
        return cpu_types.get(cpu_type)

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
            content = self.get_section_bytes(section_name)
            if content is None:
                return None

            if offset + size > len(content):
                logger.warning(f"Requested range {offset}:{offset+size} exceeds section size {len(content)}")
                return None

            return content[offset : offset + size]

        except Exception as e:
            logger.debug(f"Failed to get section bytes at offset for {section_name}: {e}")
            return None

    def get_section_bytes(self, section_name: str) -> bytes | None:
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
