"""Shared utilities for binary parsing."""

from __future__ import annotations

from typing import List

import lief

from ...utils.logging import get_logger

logger = get_logger(__name__)


def read_null_terminated_string(binary: lief.MachO.Binary, offset: int) -> str | None:
    """Read a null-terminated string from the binary.

    Args:
        binary: The LIEF binary object
        offset: Offset in the binary to start reading from

    Returns:
        The string content, or None if reading failed
    """
    try:
        # Convert file offset to virtual address
        vm_address_result = binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert file offset {offset} to virtual address")
            return None
        vm_address = vm_address_result

        # Read up to 256 bytes to find the null terminator
        content = binary.get_content_from_virtual_address(vm_address, 256, lief.Binary.VA_TYPES.AUTO)
        if not content:
            logger.debug(f"No content read at VM address {vm_address} (file offset {offset})")
            return None

        # Find the null terminator
        null_pos = -1
        for i, byte in enumerate(content):
            if byte == 0:
                null_pos = i
                break

        if null_pos == -1:
            logger.debug(f"No null terminator found in first 256 bytes at VM address {vm_address}")
            return None

        # Convert to string
        string_bytes = bytes(content[:null_pos])
        result = string_bytes.decode("utf-8", errors="ignore")

        # Log the raw bytes and decoded string for debugging
        if len(result) > 0:
            logger.debug(
                f"Read string at offset {offset} (VM {vm_address}): raw={string_bytes[:20]}, decoded='{result[:50]}'"
            )

        return result

    except Exception as e:
        logger.debug(f"Failed to read null-terminated string at offset {offset}: {e}")
        return None


def parse_null_terminated_strings(content: bytes) -> List[str]:
    """Parse multiple null-terminated strings from a byte array.

    Args:
        content: Raw bytes containing null-terminated strings

    Returns:
        List of parsed strings, excluding empty strings
    """
    try:
        strings = [
            part.decode("utf-8")
            for part in content.split(b"\x00")
            if part  # Filter out empty parts
        ]
        return strings
    except UnicodeDecodeError as e:
        logger.error(f"Failed to decode strings: {e}")
        return []
