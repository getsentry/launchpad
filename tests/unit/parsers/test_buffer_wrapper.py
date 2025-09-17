import pytest

from launchpad.parsers.buffer_wrapper import BufferWrapper


@pytest.mark.parametrize(
    "data,expected",
    [
        # 0
        (b"\x00", 0),
        # 1
        (b"\x01", 1),
        # -1
        (b"\x7f", -1),
        # 624485 (from DWARF spec)
        (b"\xe5\x8e\x26", 624485),
        # -2
        (b"\x7e", -2),
        # 127
        (b"\xff\x00", 127),
        # -127
        (b"\x81\x7f", -127),
        # 128
        (b"\x80\x01", 128),
        # -128
        (b"\x80\x7f", -128),
        # 2147483647 (0x7fffffff)
        (b"\xff\xff\xff\xff\x07", 2147483647),
        # -2147483648 (0x80000000)
        (b"\x80\x80\x80\x80\x78", -2147483648),
    ],
)
def test_read_leb128(data, expected):
    buf = BufferWrapper(data)
    result = buf.read_leb128()
    assert result == expected
    # Cursor should be at the end
    assert buf.cursor == len(data)
