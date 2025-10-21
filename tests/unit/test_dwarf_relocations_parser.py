"""Tests for DWARF relocations parser."""

from __future__ import annotations

import tempfile

from pathlib import Path

import pytest

from launchpad.parsers.apple.dwarf_relocations_parser import (
    DwarfRelocation,
    DwarfRelocationsData,
    DwarfRelocationsParser,
)


class TestDwarfRelocation:
    """Tests for DwarfRelocation dataclass."""

    def test_from_dict_valid(self):
        """Test creating DwarfRelocation from valid dictionary."""
        data = {
            "offset": 0x669BB6,
            "size": 0x8,
            "addend": 0x0,
            "symName": "_main",
            "symObjAddr": 0x0,
            "symBinAddr": 0x100004000,
            "symSize": 0x18,
        }

        relocation = DwarfRelocation.from_dict(data)

        assert relocation.offset == 0x669BB6
        assert relocation.size == 0x8
        assert relocation.addend == 0x0
        assert relocation.sym_name == "_main"
        assert relocation.sym_obj_addr == 0x0
        assert relocation.sym_bin_addr == 0x100004000
        assert relocation.sym_size == 0x18

    def test_from_dict_missing_field(self):
        """Test that missing fields raise KeyError."""
        data = {
            "offset": 0x669BB6,
            "size": 0x8,
            # Missing required fields
        }

        with pytest.raises(KeyError):
            DwarfRelocation.from_dict(data)


class TestDwarfRelocationsData:
    """Tests for DwarfRelocationsData dataclass."""

    def test_total_relocation_size(self):
        """Test calculating total relocation size."""
        relocations = [
            DwarfRelocation(0x1000, 8, 0, "_main", 0x0, 0x100004000, 0x18),
            DwarfRelocation(0x1008, 8, 0, "_foo", 0x18, 0x100004018, 0x100),
            DwarfRelocation(0x1010, 8, 0, "_bar", 0x118, 0x100004118, 0x50),
        ]

        data = DwarfRelocationsData("arm64-apple-darwin", "/path/to/binary", relocations)

        assert data.total_relocation_size == 0x18 + 0x100 + 0x50

    def test_get_relocations_by_symbol(self):
        """Test filtering relocations by symbol name."""
        relocations = [
            DwarfRelocation(0x1000, 8, 0, "_main", 0x0, 0x100004000, 0x18),
            DwarfRelocation(0x1008, 8, 0, "_main", 0x0, 0x100004000, 0x18),
            DwarfRelocation(0x1010, 8, 0, "_foo", 0x18, 0x100004018, 0x100),
        ]

        data = DwarfRelocationsData("arm64-apple-darwin", "/path/to/binary", relocations)

        main_relocs = data.get_relocations_by_symbol("_main")
        assert len(main_relocs) == 2
        assert all(r.sym_name == "_main" for r in main_relocs)

        foo_relocs = data.get_relocations_by_symbol("_foo")
        assert len(foo_relocs) == 1
        assert foo_relocs[0].sym_name == "_foo"

        nonexistent = data.get_relocations_by_symbol("_nonexistent")
        assert len(nonexistent) == 0


class TestDwarfRelocationsParser:
    """Tests for DwarfRelocationsParser."""

    def test_parse_valid_yaml(self):
        """Test parsing valid relocations YAML."""
        yaml_content = """---
triple:          'arm64-apple-darwin'
binary-path:     '/Applications/TestApp.app/TestApp'
relocations:
  - { offset: 0x669BB6, size: 0x8, addend: 0x0, symName: _main, symObjAddr: 0x0, symBinAddr: 0x100004000, symSize: 0x18 }
  - { offset: 0x669C63, size: 0x8, addend: 0x0, symName: _main, symObjAddr: 0x0, symBinAddr: 0x100004000, symSize: 0x18 }
  - { offset: 0x669CA2, size: 0x8, addend: 0x0, symName: '_$s7TestApp4MainV4mainyyFZTf4d_n', symObjAddr: 0x18, symBinAddr: 0x100004018, symSize: 0x100 }
  - { offset: 0x669DBC, size: 0x8, addend: 0x0, symName: ___swift_noop_void_return, symObjAddr: 0x0, symBinAddr: 0x100004FD0, symSize: 0x4 }
  - { offset: 0x669DD0, size: 0x8, addend: 0x0, symName: ___swift_memcpy32_8, symObjAddr: 0x4, symBinAddr: 0x100004FD4, symSize: 0xC }
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            result = DwarfRelocationsParser.parse(temp_path)

            assert result is not None
            assert result.triple == "arm64-apple-darwin"
            assert result.binary_path == "/Applications/TestApp.app/TestApp"
            assert len(result.relocations) == 5

            # Check first relocation
            first = result.relocations[0]
            assert first.offset == 0x669BB6
            assert first.size == 0x8
            assert first.sym_name == "_main"
            assert first.sym_size == 0x18

            # Check Swift symbol
            swift_reloc = result.relocations[2]
            assert swift_reloc.sym_name == "_$s7TestApp4MainV4mainyyFZTf4d_n"
            assert swift_reloc.sym_size == 0x100
        finally:
            temp_path.unlink()

    def test_parse_empty_relocations(self):
        """Test parsing YAML with empty relocations array."""
        yaml_content = """---
triple:          'arm64-apple-darwin'
binary-path:     '/Applications/Test.app/Test'
relocations: []
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            result = DwarfRelocationsParser.parse(temp_path)

            assert result is not None
            assert result.triple == "arm64-apple-darwin"
            assert len(result.relocations) == 0
        finally:
            temp_path.unlink()

    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file returns None."""
        result = DwarfRelocationsParser.parse(Path("/nonexistent/file.yml"))
        assert result is None

    def test_parse_malformed_yaml(self):
        """Test parsing malformed YAML handles errors gracefully."""
        yaml_content = """---
triple: 'arm64-apple-darwin'
relocations:
  - { offset: 0x669BB6, size: 0x8, addend: 0x0, symName: _main }
  - { offset: invalid, size: 0x8 }
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            result = DwarfRelocationsParser.parse(temp_path)

            # Should still parse the file, but skip invalid entries
            assert result is not None
            # Only the first valid entry should be parsed, second is invalid
            assert len(result.relocations) == 0  # First entry is missing required fields
        finally:
            temp_path.unlink()

    def test_parse_empty_file(self):
        """Test parsing empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("")
            temp_path = Path(f.name)

        try:
            result = DwarfRelocationsParser.parse(temp_path)
            assert result is None
        finally:
            temp_path.unlink()
