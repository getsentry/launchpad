from __future__ import annotations

import contextlib
import struct
import typing

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

_S8 = struct.Struct("<b")
_U16 = struct.Struct("<H")
_S32 = struct.Struct("<i")
_U32 = struct.Struct("<I")
_U32BE = struct.Struct(">I")
_U64 = struct.Struct("<Q")


def group(name: str):
    def decorator(wrapped):
        def wrapper(self, *args):
            if self.debug:
                logger.debug("=== %s ===", name)
            result = wrapped(self, *args)
            if self.debug:
                logger.debug("=== End %s ===", name)
            return result

        return wrapper

    return decorator


class BufferUnderrunError(ValueError):
    """Raised when a read would go past the end of the buffer."""

    def __init__(self, cursor: int, size: int, length: int) -> None:
        super().__init__(f"Cannot read {size} bytes at offset {cursor}: buffer is only {length} bytes")


class BufferWrapper:
    """Wrapper for binary buffer parsing with cursor tracking and debugging."""

    __slots__ = "cursor", "buffer", "debug", "cache"

    def __init__(self, buffer: bytes, debug: bool = False) -> None:
        """Initialize buffer wrapper.

        Args:
            buffer: Raw bytes to parse
            debug: Whether to enable debug logging
        """
        self.buffer = buffer
        self.cursor = 0
        self.debug = debug
        self.cache: object | None = None

    def require(self, length: int) -> None:
        """Raise BufferUnderrunError unless `length` bytes remain from the cursor."""
        if length < 0 or self.cursor < 0 or self.cursor + length > len(self.buffer):
            raise BufferUnderrunError(self.cursor, length, len(self.buffer))

    def _unpack(self, fmt: struct.Struct) -> int:
        """Unpack a fixed-size value at the cursor without advancing it."""
        cursor = self.cursor
        # unpack_from treats a negative offset as relative to the end of the buffer.
        if cursor < 0:
            raise BufferUnderrunError(cursor, fmt.size, len(self.buffer))
        try:
            return fmt.unpack_from(self.buffer, cursor)[0]  # type: ignore[no-any-return]
        except struct.error:
            raise BufferUnderrunError(cursor, fmt.size, len(self.buffer)) from None

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

    @contextlib.contextmanager
    def _debug_group(self, name: str) -> typing.Iterator[None]:
        """Create debug logging context.

        Args:
            name: Name of the debug group
        """
        if self.debug:
            logger.debug("=== %s ===", name)
        yield
        if self.debug:
            logger.debug("=== End %s ===", name)

    def read_u8(self) -> int:
        """Read unsigned 8-bit integer."""
        if self.debug:
            # read_u8 is called so often it is worth embedding the
            # group() logging.
            logger.debug("=== read_u8 ===")
            logger.debug(f"cursor: {self.cursor}")
        cursor = self.cursor
        # A negative index would silently read from the end of the buffer.
        if cursor < 0:
            raise BufferUnderrunError(cursor, 1, len(self.buffer))
        try:
            val = self.buffer[cursor]
        except IndexError:
            raise BufferUnderrunError(cursor, 1, len(self.buffer)) from None
        if self.debug:
            logger.debug(f"value: {val}")
            logger.debug("=== End read_u8 ===")
        self.cursor = cursor + 1
        return val

    @group("read_s8")
    def read_s8(self) -> int:
        """Read signed 8-bit integer."""
        if self.debug:
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_S8)
        if self.debug:
            logger.debug(f"value: {val}")
        self.cursor += 1
        return val

    @group("read_u16")
    def read_u16(self) -> int:
        """Read unsigned 16-bit integer (little-endian)."""
        if self.debug:
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_U16)
        if self.debug:
            logger.debug(f"value: {val}")
        self.cursor += 2
        return val

    @group("read_s32")
    def read_s32(self) -> int:
        """Read signed 32-bit integer (little-endian)."""
        if self.debug:
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_S32)
        if self.debug:
            logger.debug(f"value: {val}")
        self.cursor += 4
        return val

    def read_u32(self) -> int:
        """Read unsigned 32-bit integer (little-endian)."""
        if self.debug:
            # read_u32 is called so often it is worth embedding the
            # group() logging.
            logger.debug("=== read_u32 ===")
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_U32)
        if self.debug:
            logger.debug(f"value: {val} 0x{val:08x}")
            logger.debug("=== End read_u32 ===")
        self.cursor += 4
        return val

    @group("read_u32be")
    def read_u32be(self) -> int:
        """Read unsigned 32-bit integer (big-endian)."""
        if self.debug:
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_U32BE)
        if self.debug:
            logger.debug(f"value: {val} 0x{val:08x}")
        self.cursor += 4
        return val

    @group("read_u64")
    def read_u64(self) -> int:
        """Read unsigned 64-bit integer (little-endian)."""
        if self.debug:
            logger.debug(f"cursor: {self.cursor}")
        val = self._unpack(_U64)
        if self.debug:
            logger.debug(f"value: {val} 0x{val:016x}")
        self.cursor += 8
        return val

    @group("read_length8")
    def read_length8(self) -> int:
        """Read length-prefixed 8-bit integer."""
        length = self.read_u8()
        if length & 0x80:
            length = ((length & 0x7F) << 8) | self.read_u8()
        if self.debug:
            logger.debug(f"length: {length}")
        return length

    @group("read_length16")
    def read_length16(self) -> int:
        """Read length-prefixed 16-bit integer."""
        length = self.read_u16()
        if length & 0x8000:
            length = ((length & 0x7FFF) << 16) | self.read_u16()
        if self.debug:
            logger.debug(f"length: {length}")
        return length

    def read_uleb128(self) -> int:
        """Read unsigned LEB128 integer.

        Each byte has 7 bits allocated for data and 1 bit (MSB) used as a continuation flag.
        The data bits are concatenated in little-endian order.
        """
        result = 0
        shift = 0
        # The cursor only moves forward below, so checking it once is enough.
        if self.cursor < 0:
            raise BufferUnderrunError(self.cursor, 1, len(self.buffer))
        while True:
            try:
                byte = self.buffer[self.cursor]
            except IndexError:
                raise BufferUnderrunError(self.cursor, 1, len(self.buffer)) from None
            self.cursor += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result

    def next_uleb128_size(self) -> int:
        """Peek the size of the next LEB128 encoded integer."""
        original_cursor = self.cursor
        self.read_uleb128()
        size = self.cursor - original_cursor
        self.cursor = original_cursor
        return size

    def read_leb128(self) -> int:
        """Read signed LEB128 integer."""
        result = 0
        shift = 0
        byte = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        # Sign extend if sign bit of last byte is set
        if (shift < 64) and (byte & 0x40):
            result |= -(1 << shift)
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
            if not 1 <= size <= 8:
                raise ValueError(f"Invalid size {size} for sized int at offset 0x{self.cursor:08x}")

            self.require(size)

            # Read bytes and sign extend
            if size == 4:
                val = self._unpack(_S32)
            else:
                # Read as unsigned and sign extend
                val = 0
                for i in range(size):
                    val |= self.buffer[self.cursor + i] << (i * 8)
                # Sign extend
                if val & (1 << ((size * 8) - 1)):
                    val |= ~((1 << (size * 8)) - 1)

            self.cursor += size
            return val

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
                raise ValueError(f"Invalid size {size} for sized uint at offset 0x{self.cursor:08x}")

            self.require(size)

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
                raise ValueError(f"Invalid size {size} for sized float at offset 0x{self.cursor:08x}")

            self.require(size)

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
                raise ValueError(f"Invalid size {size} for sized double at offset 0x{self.cursor:08x}")

            self.require(size)

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
            self.require(length)
            val = self.buffer[self.cursor : self.cursor + length].decode("utf-8", errors="replace").replace("\0", "")
            self.cursor += length
            return val

    def read_string_null_terminated(self) -> str:
        """Read null-terminated string.

        Returns:
            Decoded string
        """
        self.require(0)
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
        self.require(length)
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
