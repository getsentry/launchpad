from types import SimpleNamespace

import lief

from launchpad.size.symbols.macho_symbol_sizes import MachOSymbolSizes


def _section(name: str, segment: str, virtual_address: int, content: bytes, section_type=None):
    return SimpleNamespace(
        name=name,
        segment=SimpleNamespace(name=segment),
        virtual_address=virtual_address,
        size=len(content),
        content=memoryview(content),
        type=section_type,
    )


def _symbol(name: str, value: int):
    return SimpleNamespace(
        name=name,
        value=value,
        origin=lief.MachO.Symbol.ORIGIN.SYMTAB,
        type=lief.MachO.Symbol.TYPE.SECTION,
    )


class _FakeBinary:
    """Minimal stand-in for lief.MachO.Binary where virtual address == file offset."""

    def __init__(self, sections, symbols):
        self._sections = sections
        self.symbols = symbols

    def section_from_virtual_address(self, address: int):
        for section in self._sections:
            if section.virtual_address <= address < section.virtual_address + section.size:
                return section
        return None

    def virtual_address_to_offset(self, address: int) -> int:
        return address


def test_named_cstring_literal_does_not_absorb_following_unnamed_literals():
    # Mirrors getsentry/launchpad#678: `static const char hex[] = "0123456789abcdef";`
    # is followed in __cstring by literals that have no symbol-table entries.
    content = b"0123456789abcdef\x000x\x00writeToFile:atomically:\x00B28@?0@8@\x00"
    cstring = _section("__cstring", "__TEXT", 0x1000, content, lief.MachO.Section.TYPE.CSTRING_LITERALS)
    binary = _FakeBinary([cstring], [_symbol("_addressToString.hex", 0x1000)])

    sizes = MachOSymbolSizes(binary).get_symbol_sizes()  # type: ignore[arg-type]

    assert len(sizes) == 1
    assert sizes[0].mangled_name == "_addressToString.hex"
    assert sizes[0].size == len(b"0123456789abcdef\x00")


def test_cstring_literal_size_stops_at_next_symbol_when_closer():
    content = b"first\x00second\x00third\x00"
    cstring = _section("__cstring", "__TEXT", 0x2000, content, lief.MachO.Section.TYPE.CSTRING_LITERALS)
    binary = _FakeBinary([cstring], [_symbol("_a", 0x2000), _symbol("_b", 0x2006)])

    sizes = {s.mangled_name: s.size for s in MachOSymbolSizes(binary).get_symbol_sizes()}  # type: ignore[arg-type]

    assert sizes == {"_a": 6, "_b": 7}


def test_non_cstring_symbol_still_uses_distance_to_section_end():
    text = _section("__text", "__TEXT", 0x3000, b"\x00" * 0x40, lief.MachO.Section.TYPE.REGULAR)
    binary = _FakeBinary([text], [_symbol("_func", 0x3000)])

    sizes = MachOSymbolSizes(binary).get_symbol_sizes()  # type: ignore[arg-type]

    assert sizes[0].size == 0x40
