"""Wrapper for binary buffer parsing with cursor tracking and debugging."""

from __future__ import annotations

import struct
import types

from dataclasses import dataclass

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DebugLogContext:
    """Context manager for debug logging groups."""

    name: str

    def __enter__(self) -> None:
        """Enter debug group."""
        # logger.debug("=== %s ===", self.name)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit debug group."""
        # logger.debug("=== End %s ===", self.name)


class BufferWrapper:
    """Wrapper for binary buffer parsing with cursor tracking and debugging."""

    def __init__(self, buffer: bytes) -> None:
        """Initialize buffer wrapper.

        Args:
            buffer: Raw bytes to parse
            debug: Whether to enable debug logging
        """
        self.buffer = buffer
        self.cursor = 0

    def seek(self, offset: int) -> None:
        """Set cursor position.

        Args:
            offset: New cursor position
        """
        self.cursor = offset

    def skip(self, length: int) -> None:
        """Skip bytes.

        Args:
            length: Number of bytes to skip
        """
        self.cursor += length

    def _debug_group(self, name: str) -> DebugLogContext:
        """Create debug logging context.

        Args:
            name: Name of the debug group

        Returns:
            Debug context manager
        """
        return DebugLogContext(name)

    def read_u8(self) -> int:
        """Read unsigned 8-bit integer."""
        with self._debug_group("read_u8"):
            # logger.debug(f"cursor: {self.cursor}")
            val = self.buffer[self.cursor]
            # logger.debug(f"value: {val}")
            self.cursor += 1
            return val

    def read_s8(self) -> int:
        """Read signed 8-bit integer."""
        with self._debug_group("read_s8"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack("<b", self.buffer[self.cursor : self.cursor + 1])[0]
            # logger.debug(f"value: {val}")
            self.cursor += 1
            return val  # type: ignore[no-any-return]

    def read_u16(self) -> int:
        """Read unsigned 16-bit integer (little-endian)."""
        with self._debug_group("read_u16"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack("<H", self.buffer[self.cursor : self.cursor + 2])[0]
            # logger.debug(f"value: {val}")
            self.cursor += 2
            return val  # type: ignore[no-any-return]

    def read_s32(self) -> int:
        """Read signed 32-bit integer (little-endian)."""
        with self._debug_group("read_s32"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack("<i", self.buffer[self.cursor : self.cursor + 4])[0]
            # logger.debug(f"value: {val}")
            self.cursor += 4
            return val  # type: ignore[no-any-return]

    def read_u32(self) -> int:
        """Read unsigned 32-bit integer (little-endian)."""
        with self._debug_group("read_u32"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack("<I", self.buffer[self.cursor : self.cursor + 4])[0]
            # logger.debug(f"value: {val} 0x{val:08x}")
            self.cursor += 4
            return val  # type: ignore[no-any-return]

    def read_u32be(self) -> int:
        """Read unsigned 32-bit integer (big-endian)."""
        with self._debug_group("read_u32be"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack(">I", self.buffer[self.cursor : self.cursor + 4])[0]
            # logger.debug(f"value: {val} 0x{val:08x}")
            self.cursor += 4
            return val  # type: ignore[no-any-return]

    def read_u64(self) -> int:
        """Read unsigned 64-bit integer (little-endian)."""
        with self._debug_group("read_u64"):
            # logger.debug(f"cursor: {self.cursor}")
            val = struct.unpack("<Q", self.buffer[self.cursor : self.cursor + 8])[0]
            # logger.debug(f"value: {val} 0x{val:016x}")
            self.cursor += 8
            return val  # type: ignore[no-any-return]

    def read_length8(self) -> int:
        """Read length-prefixed 8-bit integer."""
        with self._debug_group("read_length8"):
            length = self.read_u8()
            if length & 0x80:
                length = ((length & 0x7F) << 8) | self.read_u8()
            # logger.debug(f"length: {length}")
            return length

    def read_length16(self) -> int:
        """Read length-prefixed 16-bit integer."""
        with self._debug_group("read_length16"):
            length = self.read_u16()
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | self.read_u16()
            # logger.debug(f"length: {length}")
            return length

    def read_uleb128(self) -> int:
        """Read unsigned LEB128 integer.

        Each byte has 7 bits allocated for data and 1 bit (MSB) used as a continuation flag.
        The data bits are concatenated in little-endian order.
        """
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result

    def read_leb128(self) -> int:
        """Read signed LEB128 integer."""
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                # Sign extend if necessary
                if shift < 32 and (byte & 0x40):
                    result |= ~((1 << shift) - 1)
                break
            shift += 7
        return result

    def read_sized_int(self, size: int) -> int:
        """Read signed integer of specified size.

        Args:
            size: Size in bytes (1-4)

        Returns:
            Signed integer value

        Raises:
            ValueError: If size is invalid
        """
        with self._debug_group(f"read_sized_int ({size} bytes)"):
            if not 1 <= size <= 4:
                raise ValueError(
                    f"Invalid size {size} for sized int at offset 0x{self.cursor:08x}"
                )

            # Read bytes and sign extend
            if size == 4:
                val = struct.unpack("<i", self.buffer[self.cursor : self.cursor + 4])[0]
            else:
                # Read as unsigned and sign extend
                val = 0
                for i in range(size):
                    val |= self.buffer[self.cursor + i] << (i * 8)
                # Sign extend
                if val & (1 << ((size * 8) - 1)):
                    val |= ~((1 << (size * 8)) - 1)

            self.cursor += size
            return val  # type: ignore[no-any-return]

    def read_sized_uint(self, size: int) -> int:
        """Read unsigned integer of specified size.

        Args:
            size: Size in bytes (1-4)

        Returns:
            Unsigned integer value

        Raises:
            ValueError: If size is invalid
        """
        with self._debug_group(f"read_sized_uint ({size} bytes)"):
            if not 1 <= size <= 4:
                raise ValueError(
                    f"Invalid size {size} for sized uint at offset 0x{self.cursor:08x}"
                )

            # Read bytes
            val = 0
            for i in range(size):
                val |= self.buffer[self.cursor + i] << (i * 8)

            self.cursor += size
            return val

    def read_sized_float(self, size: int) -> float:
        """Read float of specified size.

        Args:
            size: Size in bytes (1-4)

        Returns:
            Float value

        Raises:
            ValueError: If size is invalid
        """
        with self._debug_group(f"read_sized_float ({size} bytes)"):
            if not 1 <= size <= 4:
                raise ValueError(
                    f"Invalid size {size} for sized float at offset 0x{self.cursor:08x}"
                )

            # Zero extend to 4 bytes
            bytes_val = bytearray(4)
            bytes_val[4 - size :] = self.buffer[self.cursor : self.cursor + size]
            val = struct.unpack("<f", bytes_val)[0]

            self.cursor += size
            return val  # type: ignore[no-any-return]

    def read_sized_double(self, size: int) -> float:
        """Read double of specified size.

        Args:
            size: Size in bytes (1-8)

        Returns:
            Double value

        Raises:
            ValueError: If size is invalid
        """
        with self._debug_group(f"read_sized_double ({size} bytes)"):
            if not 1 <= size <= 8:
                raise ValueError(
                    f"Invalid size {size} for sized double at offset 0x{self.cursor:08x}"
                )

            # Zero extend to 8 bytes
            bytes_val = bytearray(8)
            bytes_val[8 - size :] = self.buffer[self.cursor : self.cursor + size]
            val = struct.unpack("<d", bytes_val)[0]

            self.cursor += size
            return val  # type: ignore[no-any-return]

    def read_string_with_length(self, length: int) -> str:
        """Read string of specified length.

        Args:
            length: String length in bytes

        Returns:
            Decoded string with null bytes removed
        """
        with self._debug_group(f"read_string ({length} bytes)"):
            val = (
                self.buffer[self.cursor : self.cursor + length]
                .decode("utf-8", errors="replace")
                .replace("\0", "")
            )
            self.cursor += length
            return val

    def read_string_null_terminated(self) -> str:
        """Read null-terminated string.

        Returns:
            Decoded string
        """
        end = self.cursor
        while end < len(self.buffer) and self.buffer[end] != 0:
            end += 1
        val = self.buffer[self.cursor : end].decode("utf-8", errors="replace")
        self.cursor = end + 1
        return val

    def maybe_read_string_null_terminated(self) -> str | None:
        """Read null-terminated string if it exists.

        Returns:
            Decoded string or None if empty or special marker
        """
        val = self.read_string_null_terminated()
        return None if not val or val == "\x01" else val

    def slice(self, length: int) -> bytes:
        """Get slice of buffer.

        Args:
            length: Length of slice

        Returns:
            Slice of buffer
        """
        val = self.buffer[self.cursor : self.cursor + length]
        self.cursor += length
        return val

    def align_buffer(self, alignment: int = 4) -> None:
        """Align cursor to specified boundary.

        Args:
            alignment: Alignment boundary (default: 4)
        """
        if self.cursor % alignment != 0:
            self.skip(alignment - (self.cursor % alignment))
