"""Tests for linkmap parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from launchpad.parsers.apple.linkmap_parser import LinkmapParser


@pytest.fixture
def hackernews_parser(hackernews_linkmap: Path) -> LinkmapParser:
    """Parsed HackerNews linkmap."""
    return LinkmapParser.from_path(hackernews_linkmap)


class TestHackerNewsLinkmap:
    """Integration tests using real HackerNews linkmap."""

    def test_parse_object_files_count(self, hackernews_parser: LinkmapParser):
        """Test that we parse the expected number of object files."""
        assert len(hackernews_parser.objs) == 496
        assert hackernews_parser.objs[0].file == "linker synthesized"

    def test_parse_specific_object_files(self, hackernews_parser: LinkmapParser):
        """Test parsing specific known object files."""
        obj_files = {obj.file: obj for obj in hackernews_parser.objs}

        # Check HackerNews app object files
        assert "LoginRow.o" in obj_files
        assert "ContentView.o" in obj_files
        assert "HNApp.o" in obj_files

        # Check library objects
        assert "SwiftSoup.o" in obj_files
        assert "SentrySwiftUI.o" in obj_files

    def test_parse_framework_libraries(self, hackernews_parser: LinkmapParser):
        """Test that framework libraries are correctly extracted."""
        sentry_objs = [obj for obj in hackernews_parser.objs if obj.library == "Sentry.framework"]

        assert len(sentry_objs) == 376
        sentry_files = {obj.file for obj in sentry_objs}
        assert "SentryCrashScopeObserver.o" in sentry_files
        assert "SentryAppStartMeasurement.o" in sentry_files

    def test_parse_sections(self, hackernews_parser: LinkmapParser):
        """Test that sections are parsed correctly."""
        assert len(hackernews_parser._sects) == 51

        sections = {sect.name: sect for sect in hackernews_parser._sects}

        assert "__text" in sections
        text_sect = sections["__text"]
        assert text_sect.seg == "__TEXT"
        assert text_sect.addr == 0x100004000
        assert text_sect.size == 0x1CFDDC

        assert "__data" in sections and "__const" in sections

    def test_parse_symbols_count(self, hackernews_parser: LinkmapParser):
        """Test that symbols are parsed (excluding zero-size symbols)."""
        assert len(hackernews_parser.syms) == 51222

    def test_parse_specific_symbols(self, hackernews_parser: LinkmapParser):
        """Test parsing specific known symbols."""
        symbol_names = {sym.name: sym for sym in hackernews_parser.syms}

        login_row_symbol = "_$s10HackerNews8LoginRowV4bodyQrvg"
        assert login_row_symbol in symbol_names

        sym = symbol_names[login_row_symbol]
        assert sym.addr == 0x100004000
        assert sym.size == 0x524
        assert sym.obj_idx == 1

    def test_symbol_to_object_linking(self, hackernews_parser: LinkmapParser):
        """Test that symbols are correctly linked to their object files."""
        login_row_sym = next(
            (sym for sym in hackernews_parser.syms if sym.name == "_$s10HackerNews8LoginRowV4bodyQrvg"), None
        )

        assert login_row_sym is not None
        assert login_row_sym.obj is not None
        assert login_row_sym.obj.file == "LoginRow.o"
        assert login_row_sym in login_row_sym.obj.syms

    def test_symbol_has_section(self, hackernews_parser: LinkmapParser):
        """Test that symbols have their sections assigned."""
        for sym in hackernews_parser.syms[:10]:
            assert sym.sect is not None
            assert sym.sect.seg in ["__TEXT", "__DATA", "__DATA_CONST"]

    def test_symbolicate_exact_address(self, hackernews_parser: LinkmapParser):
        """Test symbolication with exact symbol start address."""
        # LoginRow body getter starts at 0x100004000
        sym = hackernews_parser.symbolicate(0x100004000)

        assert sym is not None
        assert sym.name == "_$s10HackerNews8LoginRowV4bodyQrvg"
        assert sym.addr == 0x100004000
        assert sym.size == 0x524

    def test_symbolicate_within_symbol(self, hackernews_parser: LinkmapParser):
        """Test symbolication with address in middle of symbol."""
        sym = hackernews_parser.symbolicate(0x100004200)
        assert sym is not None
        assert sym.name == "_$s10HackerNews8LoginRowV4bodyQrvg"

    def test_symbolicate_at_symbol_boundary(self, hackernews_parser: LinkmapParser):
        """Test symbolication at the end boundary of a symbol."""
        sym_at_end = hackernews_parser.symbolicate(0x100004523)
        assert sym_at_end is not None
        assert sym_at_end.name == "_$s10HackerNews8LoginRowV4bodyQrvg"

        sym_next = hackernews_parser.symbolicate(0x100004524)
        assert sym_next is not None
        assert sym_next.name != "_$s10HackerNews8LoginRowV4bodyQrvg"

    def test_symbolicate_out_of_range(self, hackernews_parser: LinkmapParser):
        """Test symbolication with addresses outside symbol ranges."""
        # Address before any symbols
        assert hackernews_parser.symbolicate(0x100000000) is None

        # Address way past all symbols
        assert hackernews_parser.symbolicate(0x200000000) is None

    def test_zero_size_symbols_filtered(self, hackernews_parser: LinkmapParser):
        """Test that zero-size symbols are filtered out."""
        for sym in hackernews_parser.syms:
            assert sym.size > 0

    def test_libc_plus_plus_library(self, hackernews_parser: LinkmapParser):
        """Test parsing of .tbd library references."""
        # Object file [37] is libc++.tbd
        tbd_objs = [obj for obj in hackernews_parser.objs if obj.file == "libc++.tbd"]
        assert len(tbd_objs) == 1


class TestLinkmapParserBasics:
    """Basic parser tests with synthetic data."""

    def test_empty_linkmap(self):
        """Test parsing an empty linkmap."""
        empty_linkmap = """# Path: /Test
# Arch: arm64
# Object files:
# Sections:
# Symbols:
"""
        parser = LinkmapParser(empty_linkmap)
        assert len(parser.objs) == 0
        assert len(parser.syms) == 0
        assert len(parser._sects) == 0

    def test_missing_required_sections(self):
        """Test handling of linkmap with missing required sections."""
        incomplete = """# Path: /Test
# Arch: arm64
"""
        parser = LinkmapParser(incomplete)
        assert len(parser.objs) == 0
        assert len(parser.syms) == 0

    def test_library_archive_parsing(self):
        """Test parsing library archive format."""
        linkmap = """# Path: /Test
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] /path/to/libFoo.a(Object1.o)
[  2] /path/to/Framework.framework/Framework(Object2.o)
# Sections:
# Address	Size    	Segment	Section
0x100004000	0x00001000	__TEXT	__text
# Symbols:
# Address	Size    	File  Name
0x100004000	0x00000100	[  1] _foo_function
0x100004100	0x00000100	[  2] _framework_function
# Dead Stripped Symbols:
"""
        parser = LinkmapParser(linkmap)

        assert len(parser.objs) == 3
        assert parser.objs[1].file == "Object1.o"
        assert parser.objs[1].library == "libFoo.a"
        assert parser.objs[2].file == "Object2.o"
        assert parser.objs[2].library == "Framework.framework"
