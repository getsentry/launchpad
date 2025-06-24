"""Integration tests for Swift protocol conformance parsing."""

from pathlib import Path

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.parsers.apple.macho_parser import MachOParser


def create_macho_parser_from_xcarchive(xcarchive_path: Path) -> MachOParser:
    with open(xcarchive_path, "rb") as f:
        archive = ZippedXCArchive(xcarchive_path, f.read())

    binary_path = archive.get_binary_path()
    assert binary_path is not None, "Failed to find main binary in xcarchive"

    import lief

    fat_binary = lief.MachO.parse(str(binary_path))  # type: ignore
    assert fat_binary is not None, "Failed to parse binary with LIEF"

    binary = fat_binary.at(0)
    return MachOParser(binary)


class TestMachOParser:
    """Test Mach-O parser against real binaries."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    def test_hackernews_parsing(self, sample_app_path: Path) -> None:
        """Test parsing Swift protocol conformances from the HackerNews app."""
        macho_parser = create_macho_parser_from_xcarchive(sample_app_path)

        architectures = macho_parser.extract_architectures()
        assert architectures == ["CPU_TYPE.ARM64"]

        linked_libraries = macho_parser.extract_linked_libraries()
        assert len(linked_libraries) == 48
        assert linked_libraries[0] == "@rpath/Common.framework/Common"

        sections = macho_parser.extract_sections()
        assert len(sections) == 50
        assert sections["__text"] == 1828412
        assert sections["__swift5_proto"] == 1200

        swift_conformances = macho_parser.parse_swift_protocol_conformances()
        assert len(swift_conformances) == 286
        assert swift_conformances[0] == "_$ss35_HasCustomAnyHashableRepresentationMp"

        imported_symbols = macho_parser.get_imported_symbols()
        assert len(imported_symbols) == 2019
        assert imported_symbols[0] == "_$s10Foundation4DateV6CommonE14timeAgoDisplaySSyF"
