"""Tests for linkmap parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from launchpad.parsers.apple.linkmap_parser import (
    LinkmapObjectFile,
    LinkmapParser,
    LinkmapSection,
    LinkmapSymbol,
)


class SimpleSectionMap:
    """Simple section map for testing that accepts all addresses."""

    def find(self, addr: int) -> LinkmapSection | None:
        """Return a dummy section for any valid address."""
        if addr >= 0x100000000:
            return LinkmapSection(addr=0x100000000, size=0x10000000, seg="__TEXT", name="__text")
        return None


class TestLinkmapParser:
    """Tests for LinkmapParser."""

    @pytest.fixture
    def sample_linkmap_path(self) -> Path:
        """Path to sample linkmap fixture."""
        return Path(__file__).parent.parent.parent.parent / "_fixtures/ios/linkmaps/HackerNews-Release-sample.txt"

    @pytest.fixture
    def sample_linkmap_contents(self) -> str:
        """Sample linkmap contents for testing."""
        return """# Path: /Applications/Test.app/Test
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] /path/to/Main.o
[  2] /path/to/Helper.o
[  3] /path/to/lib.a(Archive.o)
# Sections:
# Address	Size    	Segment	Section
0x100004000	0x00001000	__TEXT	__text
0x100005000	0x00000100	__TEXT	__stubs
0x100006000	0x00000200	__DATA	__data
# Symbols:
# Address	Size    	File  Name
0x100004000	0x00000100	[  1] _main
0x100004100	0x00000050	[  1] _helper_function
0x100004150	0x00000080	[  2] _utility_function
0x100004200	0x00000100	[  3] _archive_function
# Dead Stripped Symbols:
0x100005000	0x00000010	[  1] _unused_function
"""

    def test_parse_basic_structure(self, sample_linkmap_contents: str):
        """Test parsing basic linkmap structure."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        assert len(parser.objs) == 4
        assert len(parser.syms) == 4
        assert len(parser._sects) == 3

    def test_parse_object_files(self, sample_linkmap_contents: str):
        """Test parsing object files section."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        # Check linker synthesized
        assert parser.objs[0].file == "linker synthesized"
        assert parser.objs[0].library is None

        # Check regular object file
        assert parser.objs[1].file == "Main.o"
        assert parser.objs[1].library is None

        # Check library archive object file
        assert parser.objs[3].file == "Archive.o"
        assert parser.objs[3].library == "lib.a"

    def test_parse_sections(self, sample_linkmap_contents: str):
        """Test parsing sections section."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        assert len(parser._sects) == 3

        text_sect = parser._sects[0]
        assert text_sect.addr == 0x100004000
        assert text_sect.size == 0x00001000
        assert text_sect.seg == "__TEXT"
        assert text_sect.name == "__text"

        data_sect = parser._sects[2]
        assert data_sect.addr == 0x100006000
        assert data_sect.size == 0x00000200
        assert data_sect.seg == "__DATA"
        assert data_sect.name == "__data"

    def test_parse_symbols(self, sample_linkmap_contents: str):
        """Test parsing symbols section."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        assert len(parser.syms) == 4

        main_sym = parser.syms[0]
        assert main_sym.addr == 0x100004000
        assert main_sym.size == 0x00000100
        assert main_sym.name == "_main"
        assert main_sym.obj_idx == 1

        archive_sym = parser.syms[3]
        assert archive_sym.addr == 0x100004200
        assert archive_sym.size == 0x00000100
        assert archive_sym.name == "_archive_function"
        assert archive_sym.obj_idx == 3

    def test_symbols_linked_to_objects(self, sample_linkmap_contents: str):
        """Test that symbols are properly linked to their object files."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        main_sym = parser.syms[0]
        assert main_sym.obj is not None
        assert main_sym.obj.file == "Main.o"

        archive_sym = parser.syms[3]
        assert archive_sym.obj is not None
        assert archive_sym.obj.file == "Archive.o"
        assert archive_sym.obj.library == "lib.a"

        # Check that objects have their symbols
        main_obj = parser.objs[1]
        assert len(main_obj.syms) == 2
        assert "_main" in [s.name for s in main_obj.syms]
        assert "_helper_function" in [s.name for s in main_obj.syms]

    def test_symbolicate_exact_address(self, sample_linkmap_contents: str):
        """Test symbolication with exact symbol address."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        sym = parser.symbolicate(0x100004000)
        assert sym is not None
        assert sym.name == "_main"

    def test_symbolicate_within_symbol(self, sample_linkmap_contents: str):
        """Test symbolication with address within symbol range."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        # Address 0x100004050 is within _main (0x100004000-0x100004100)
        sym = parser.symbolicate(0x100004050)
        assert sym is not None
        assert sym.name == "_main"

        # Address 0x100004120 is within _helper_function
        sym = parser.symbolicate(0x100004120)
        assert sym is not None
        assert sym.name == "_helper_function"

    def test_symbolicate_out_of_range(self, sample_linkmap_contents: str):
        """Test symbolication with address out of range."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        # Address before first symbol
        sym = parser.symbolicate(0x100000000)
        assert sym is None

        # Address after last symbol
        sym = parser.symbolicate(0x200000000)
        assert sym is None

    def test_symbolicate_empty_parser(self):
        """Test symbolication with empty parser."""
        empty_linkmap = """# Path: /Test
# Arch: arm64
# Object files:
# Sections:
# Symbols:
"""
        parser = LinkmapParser(empty_linkmap, None)

        sym = parser.symbolicate(0x100004000)
        assert sym is None

    def test_filter_zero_size_symbols(self):
        """Test that symbols with zero size are filtered out."""
        linkmap = """# Path: /Test
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] /path/to/Main.o
# Sections:
# Address	Size    	Segment	Section
0x100004000	0x00001000	__TEXT	__text
# Symbols:
# Address	Size    	File  Name
0x100004000	0x00000000	[  0] __mh_execute_header
0x100004000	0x00000000	[  0] ___dso_handle
0x100004000	0x00000100	[  1] _main
# Dead Stripped Symbols:
"""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(linkmap, section_map)

        # Only _main should be included (others have size 0)
        assert len(parser.syms) == 1
        assert parser.syms[0].name == "_main"

    def test_section_assignment(self, sample_linkmap_contents: str):
        """Test that symbols are assigned to correct sections."""
        section_map = SimpleSectionMap()
        parser = LinkmapParser(sample_linkmap_contents, section_map)

        # Symbols in __text section
        main_sym = parser.syms[0]
        assert main_sym.sect.seg == "__TEXT"
        assert main_sym.sect.name == "__text"

    def test_from_path_classmethod(self, sample_linkmap_path: Path):
        """Test creating parser from file path."""
        if not sample_linkmap_path.exists():
            pytest.skip("Sample linkmap fixture not found")

        section_map = SimpleSectionMap()
        parser = LinkmapParser.from_path(sample_linkmap_path, section_map)

        assert len(parser.objs) > 0
        assert len(parser.syms) > 0
        assert len(parser._sects) > 0

        # Check some expected content from the HackerNews sample
        obj_names = [obj.file for obj in parser.objs]
        assert "linker synthesized" in obj_names
        assert any("LoginRow.o" in name for name in obj_names)

    def test_real_swift_symbols(self, sample_linkmap_path: Path):
        """Test parsing real Swift mangled symbols."""
        if not sample_linkmap_path.exists():
            pytest.skip("Sample linkmap fixture not found")

        section_map = SimpleSectionMap()
        parser = LinkmapParser.from_path(sample_linkmap_path, section_map)

        # Find a Swift mangled symbol
        swift_syms = [s for s in parser.syms if s.name.startswith("_$s")]
        assert len(swift_syms) > 0

        # Verify they have proper sizes and object links
        for sym in swift_syms[:5]:
            assert sym.size > 0
            assert sym.obj is not None
            assert sym.sect is not None

    def test_library_object_parsing(self, sample_linkmap_path: Path):
        """Test parsing library archive objects (framework files)."""
        if not sample_linkmap_path.exists():
            pytest.skip("Sample linkmap fixture not found")

        section_map = SimpleSectionMap()
        parser = LinkmapParser.from_path(sample_linkmap_path, section_map)

        # Look for framework library objects like Sentry.framework/Sentry(*.o)
        framework_objs = [obj for obj in parser.objs if "Sentry.framework" in (obj.library or "")]
        assert len(framework_objs) > 0

        # Verify they're parsed correctly
        for obj in framework_objs[:5]:
            assert obj.library == "Sentry.framework"
            assert obj.file.endswith(".o")

    def test_missing_sections_handling(self):
        """Test handling of linkmap with missing sections."""
        incomplete_linkmap = """# Path: /Test
# Arch: arm64
"""
        parser = LinkmapParser(incomplete_linkmap, None)

        assert len(parser.objs) == 0
        assert len(parser.syms) == 0
        assert len(parser._sects) == 0

    def test_section_map_filtering(self):
        """Test that section_map properly filters symbols."""

        class RestrictiveSectionMap:
            """Section map that only accepts specific address range."""

            def find(self, addr: int) -> LinkmapSection | None:
                if 0x100004000 <= addr < 0x100005000:
                    return LinkmapSection(addr=0x100004000, size=0x1000, seg="__TEXT", name="__text")
                return None

        linkmap = """# Path: /Test
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] /path/to/Main.o
# Sections:
# Address	Size    	Segment	Section
0x100004000	0x00001000	__TEXT	__text
0x100006000	0x00001000	__DATA	__data
# Symbols:
# Address	Size    	File  Name
0x100004000	0x00000100	[  1] _in_range
0x100006000	0x00000100	[  1] _out_of_range
# Dead Stripped Symbols:
"""
        section_map = RestrictiveSectionMap()
        parser = LinkmapParser(linkmap, section_map)

        # Only the symbol in range should be included
        assert len(parser.syms) == 1
        assert parser.syms[0].name == "_in_range"


class TestLinkmapObjectFile:
    """Tests for LinkmapObjectFile dataclass."""

    def test_object_file_creation(self):
        """Test creating a LinkmapObjectFile."""
        obj = LinkmapObjectFile(file="Main.o", line_name="/path/to/Main.o", library=None, line="[  1] /path/to/Main.o")

        assert obj.file == "Main.o"
        assert obj.line_name == "/path/to/Main.o"
        assert obj.library is None
        assert len(obj.syms) == 0

    def test_object_file_with_library(self):
        """Test creating a LinkmapObjectFile from a library."""
        obj = LinkmapObjectFile(
            file="Archive.o",
            line_name="lib.a(Archive.o)",
            library="lib.a",
            line="[  3] /path/to/lib.a(Archive.o)",
        )

        assert obj.file == "Archive.o"
        assert obj.library == "lib.a"

    def test_repr(self):
        """Test LinkmapObjectFile repr."""
        obj = LinkmapObjectFile(file="Main.o", line_name="/path/to/Main.o", library=None, line="")
        repr_str = repr(obj)
        assert "Main.o" in repr_str


class TestLinkmapSymbol:
    """Tests for LinkmapSymbol dataclass."""

    def test_sym_creation(self):
        """Test creating a LinkmapSymbol."""
        sect = LinkmapSection(addr=0x100004000, size=0x1000, seg="__TEXT", name="__text")
        sym = LinkmapSymbol(addr=0x100004000, name="_main", size=0x100, obj_idx=1, sect=sect)

        assert sym.addr == 0x100004000
        assert sym.name == "_main"
        assert sym.size == 0x100
        assert sym.obj_idx == 1
        assert sym.sect == sect
        assert sym.obj is None

    def test_repr(self):
        """Test LinkmapSymbol repr."""
        sect = LinkmapSection(addr=0x100004000, size=0x1000, seg="__TEXT", name="__text")
        sym = LinkmapSymbol(addr=0x100004000, name="_main", size=0x100, obj_idx=1, sect=sect)
        repr_str = repr(sym)
        assert "_main" in repr_str
        assert "0x100004000" in repr_str


class TestLinkmapSection:
    """Tests for LinkmapSection dataclass."""

    def test_section_creation(self):
        """Test creating a LinkmapSection."""
        sect = LinkmapSection(addr=0x100004000, size=0x1000, seg="__TEXT", name="__text")

        assert sect.addr == 0x100004000
        assert sect.size == 0x1000
        assert sect.seg == "__TEXT"
        assert sect.name == "__text"

    def test_repr(self):
        """Test LinkmapSection repr."""
        sect = LinkmapSection(addr=0x100004000, size=0x1000, seg="__TEXT", name="__text")
        repr_str = repr(sect)
        assert "__TEXT" in repr_str
        assert "__text" in repr_str
