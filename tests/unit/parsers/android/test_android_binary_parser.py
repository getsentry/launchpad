import struct

import pytest

from launchpad.artifacts.android.resources.binary import BinaryResourceTable
from launchpad.parsers.android.binary.android_binary_parser import AndroidBinaryParser


def _chunk_header(chunk_type: int, header_size: int, chunk_size: int) -> bytes:
    return struct.pack("<HHI", chunk_type, header_size, chunk_size)


def _resource_table(trailing: bytes = b"", declared_size_delta: int = 0) -> bytes:
    # TABLE root (12-byte header incl. package count) wrapping a single 32-byte NULL chunk.
    null_chunk = _chunk_header(0x0000, 8, 32 + declared_size_delta) + b"\x00" * 24
    body = struct.pack("<I", 0) + null_chunk
    return _chunk_header(0x0002, 12, 8 + len(body) + declared_size_delta) + body + trailing


def test_truncated_resource_table_raises_value_error():
    # A resources.arsc truncated to 4 bytes, as seen in a malformed uploaded APK.
    with pytest.raises(ValueError, match="Cannot read 4 bytes at offset 4"):
        BinaryResourceTable(b"\x02\x00\x0c\x00")


def test_resource_table_ignores_padding_after_root_chunk():
    table = BinaryResourceTable(_resource_table(trailing=b"\x00\x00\x00\x00"))
    assert table.binary_parser.packages == []


def test_resource_table_tolerates_last_chunk_running_past_eof():
    table = BinaryResourceTable(_resource_table(declared_size_delta=4))
    assert table.binary_parser.packages == []


def test_unterminated_package_name_raises_value_error():
    package_header = _chunk_header(0x0200, 288, 288) + struct.pack("<I", 0x7F) + "A".encode("utf-16le") * 128
    body = struct.pack("<I", 1) + package_header
    buffer = _chunk_header(0x0002, 12, 8 + len(body)) + body
    with pytest.raises(ValueError, match="Package name is not NUL-terminated"):
        BinaryResourceTable(buffer)


def test_truncated_package_name_raises_value_error():
    package_header = _chunk_header(0x0200, 288, 288) + struct.pack("<I", 0x7F) + b"\x00" * 64
    body = struct.pack("<I", 1) + package_header
    buffer = _chunk_header(0x0002, 12, 8 + len(body)) + body
    with pytest.raises(ValueError, match="Cannot read 256 bytes"):
        BinaryResourceTable(buffer)


@pytest.mark.parametrize(
    "header_size,chunk_size",
    [
        (8, 0),  # zero-size chunk would otherwise loop forever
        (0, 8),  # header smaller than a chunk header
        (16, 8),  # header larger than its chunk
    ],
)
def test_xml_with_invalid_chunk_raises_value_error(header_size, chunk_size):
    padding = b"\x00" * 16
    buffer = _chunk_header(0x0003, 8, 8 + 8 + len(padding)) + _chunk_header(0x0000, header_size, chunk_size) + padding
    with pytest.raises(ValueError, match="Invalid chunk at offset 8"):
        AndroidBinaryParser(buffer).parse_xml()
