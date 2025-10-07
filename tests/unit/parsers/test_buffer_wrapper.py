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


def test_read_u8(benchmark):
    buffer = b"\x42"
    wrapper = BufferWrapper(buffer)
    assert wrapper.read_u8() == 0x42


def test_benchmark_read_u8(benchmark):
    buffer = b"\x42"
    wrapper = BufferWrapper(buffer)

    def parse():
        wrapper.seek(0)
        return wrapper.read_u8()

    final = benchmark(parse)
    assert final == 0x42


def test_benchmark_read_u32(benchmark):
    buffer = b"\x01\x02\x04\x08"
    wrapper = BufferWrapper(buffer)

    def parse():
        wrapper.seek(0)
        return wrapper.read_u32()

    final = benchmark(parse)
    assert final == (0x01) + (0x02 << 8) + (0x04 << 16) + (0x08 << 24)


def test_benchmark_read_uleb128(benchmark):
    pairs = [
        (b"\x00", 0),
        (b"\x01", 1),
        (b"\xe5\x8e\x26", 624485),
        (b"\xff\x00", 127),
        (b"\x80\x01", 128),
        (b"\xff\xff\xff\xff\x07", 2147483647),
    ]

    buffer = b"".join([buf for buf, _ in pairs])
    expected_total = sum([value for _, value in pairs])
    wrapper = BufferWrapper(buffer)

    def parse():
        wrapper.seek(0)
        total = 0
        for _ in range(len(pairs)):
            total += wrapper.read_uleb128()
        return total

    final = benchmark(parse)
    assert final == expected_total
