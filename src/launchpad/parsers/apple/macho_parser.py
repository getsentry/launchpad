"""Mach-O binary parser using LIEF."""

from __future__ import annotations

import struct

from pathlib import Path
from typing import Dict, List

import lief

from ...utils.logging import get_logger
from .binary_utils import parse_null_terminated_strings
from .chained_fixups_parser import ChainedFixupsParser
from .code_signature_parser import CodeSignatureParser, CodeSignInformation
from .swift_protocol_parser import SwiftProtocolParser

logger = get_logger(__name__)


class MachOParser:
    """Parser for Mach-O binaries using LIEF."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        """Initialize the parser with a LIEF binary object."""
        self.binary = binary
        self._imported_symbols_cache: List[str] | None = None

    @staticmethod
    def is_macho_binary(file_path: Path) -> bool:
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                return magic in [
                    b"\xfe\xed\xfa\xce",  # MH_MAGIC
                    b"\xce\xfa\xed\xfe",  # MH_CIGAM
                    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
                    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
                    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
                    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
                ]
        except Exception:
            return False

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
                logger.warning(f"Requested range {offset}:{offset + size} exceeds section size {len(content)}")
                return None

            return content[offset : offset + size]

        except Exception as e:
            logger.error(f"Failed to get section bytes at offset for {section_name}: {e}")
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
            logger.error(f"Failed to get section content for {section_name}: {e}")
            return None

    def is_encrypted(self) -> bool:
        """Check if the Mach-O binary is encrypted.

        Returns:
            True if the binary is encrypted, False otherwise
        """
        try:
            # Check if the binary has encryption info
            if not self.binary.has_encryption_info:
                return False

            # If encryption_info exists and crypt_id is non-zero, the binary is encrypted
            return bool(self.binary.encryption_info.crypt_id)
        except Exception as e:
            logger.error(f"Failed to check encryption status: {e}")
            return False

    def parse_swift_protocol_conformances(self) -> List[str]:
        """Parse the Swift protocol section."""
        return SwiftProtocolParser(self.binary, self).parse_swift_protocol_conformances()

    def read_indirect_pointer(self, offset: int) -> tuple[int, int]:
        """Read an indirect pointer from the binary.

        This is a shared function that reads relative pointers used in Swift metadata.
        Returns a tuple of (pointer_value, bytes_consumed).
        """
        vm_address_result = self.binary.offset_to_virtual_address(offset)

        # Handle the union type - check if it's an error
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return (0, 4)  # Return 0 as fallback for error cases, consumed 4 bytes

        vm_address = vm_address_result
        indirect_offset = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if indirect_offset is None:
            logger.debug(f"Failed to convert offset {offset} to virtual address: {indirect_offset}")
            return (0, 4)  # Return 0 as fallback for error cases, consumed 4 bytes

        if indirect_offset % 2 == 1:
            contents = self.binary.get_content_from_virtual_address(
                vm_address + (indirect_offset & ~0x1), 8, lief.Binary.VA_TYPES.AUTO
            )
            return (int.from_bytes(contents, byteorder="little"), 4)  # Consumed 4 bytes
        else:
            return (vm_address + indirect_offset, 4)  # Consumed 4 bytes

    def parse_code_signature(self) -> CodeSignInformation | None:
        """Parse the code signature information from the binary."""
        return CodeSignatureParser(self.binary, self).parse_code_signature()

    def get_imported_symbols(self) -> List[str]:
        if self._imported_symbols_cache is not None:
            return self._imported_symbols_cache

        parser = ChainedFixupsParser(self.binary)
        self._imported_symbols_cache = parser.parse_imported_symbols()

        return self._imported_symbols_cache

    def parse_objc_method_names(self) -> List[str]:
        """Parse Objective-C method names from the __objc_methname section.

        Extracts all null-terminated strings from the __objc_methname section,
        which contains the method names used in the Objective-C runtime.

        Returns:
            List of method names found in the section, or empty list if section not found
        """
        try:
            content = self.get_section_bytes("__objc_methname")
            if content is None:
                logger.debug("__objc_methname section not found")
                return []

            method_names = parse_null_terminated_strings(content)
            logger.debug(f"Parsed {len(method_names)} Objective-C method names")
            return method_names

        except Exception as e:
            logger.error(f"Failed to parse Objective-C method names: {e}")
            return []

    def has_swift_imageinfo(self) -> bool:
        """Check if the binary has Swift image info with non-zero Swift version.

        This corresponds to the -T flag behavior in strip, which only removes Swift symbols
        if __objc_imageinfo section exists and has a non-zero Swift version.

        Returns:
            True if Swift image info is present with non-zero Swift version
        """
        try:
            sec = self.binary.get_section("__objc_imageinfo")
            if sec and len(sec.content) >= 8:
                _, flags = struct.unpack_from("<II", sec.content)  # Mach-O is LE on modern HW
                swift_version = (flags >> 8) & 0xFF
                has_swift_info = swift_version != 0
                logger.debug(
                    "objc_imageinfo flags=0x%08x  swift=%d  objcFlags=0x%02x", flags, swift_version, flags & 0xFF
                )
                return has_swift_info
            return False
        except Exception as e:
            logger.error("Could not parse __objc_imageinfo: %s", e)
            return False
