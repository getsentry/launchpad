"""Integration tests for iOS analyzer with range mapping."""

from unittest.mock import Mock

from launchpad.analyzers.ios import IOSAnalyzer
from launchpad.models.range_mapping import BinaryTag
from launchpad.parsers.ios.macho_parser import MachOParser
from launchpad.parsers.ios.range_mapping_builder import RangeMappingBuilder


class TestIOSAnalyzerRangeMapping:
    """Test iOS analyzer integration with range mapping."""

    def test_range_mapping_enabled_by_default(self) -> None:
        """Test that range mapping is enabled by default."""
        analyzer = IOSAnalyzer()
        assert analyzer.enable_range_mapping is True

    def test_range_mapping_can_be_disabled(self) -> None:
        """Test that range mapping can be disabled."""
        analyzer = IOSAnalyzer(enable_range_mapping=False)
        assert analyzer.enable_range_mapping is False

    def test_range_mapping_creation(self) -> None:
        """Test that range mapping is created during binary analysis."""
        # Create a mock binary with basic attributes
        mock_binary = Mock()
        mock_binary.header = Mock()
        mock_binary.header.sizeof = 32
        mock_binary.commands = []
        mock_binary.sections = []
        mock_binary.symbols = []
        mock_binary.libraries = []

        # Create parser and test range mapping creation
        parser = MachOParser(mock_binary)
        range_builder = RangeMappingBuilder(parser, 1024)
        range_map = range_builder.build_range_mapping()

        # Verify range map was created
        assert range_map is not None
        assert range_map.total_file_size == 1024

        # Verify header was mapped
        assert len(range_map.ranges) > 0

        # Check that header range was added
        header_ranges = [r for r in range_map.ranges if r.tag == BinaryTag.HEADERS]
        assert len(header_ranges) == 1
        assert header_ranges[0].start == 0
        assert header_ranges[0].end == 32  # Mock header size

    def test_section_categorization(self) -> None:
        """Test that sections are categorized correctly."""
        # Create a mock binary
        mock_binary = Mock()
        parser = MachOParser(mock_binary)
        range_builder = RangeMappingBuilder(parser, 1000)

        # Test various section names
        test_cases = [
            ("__text", BinaryTag.TEXT_SEGMENT),
            ("__TEXT", BinaryTag.TEXT_SEGMENT),
            ("__stubs", BinaryTag.TEXT_SEGMENT),
            ("__swift5_types", BinaryTag.SWIFT_METADATA),
            ("__objc_classlist", BinaryTag.OBJC_CLASSES),
            ("__cstring", BinaryTag.C_STRINGS),
            ("__cfstring", BinaryTag.C_STRINGS),
            ("__data", BinaryTag.DATA_SEGMENT),
            ("__const", BinaryTag.CONST_DATA),
            ("__unwind_info", BinaryTag.UNWIND_INFO),
            ("__eh_frame", BinaryTag.UNWIND_INFO),
            ("unknown_section", BinaryTag.DATA_SEGMENT),  # Default case
        ]

        for section_name, expected_tag in test_cases:
            result_tag = range_builder._categorize_section(section_name)
            assert (
                result_tag == expected_tag
            ), f"Section {section_name} should be categorized as {expected_tag}, got {result_tag}"

    def test_section_mapping(self) -> None:
        """Test that sections are properly mapped to ranges."""
        # Create mock sections
        mock_section1 = Mock()
        mock_section1.name = "__text"
        mock_section1.offset = 100
        mock_section1.size = 500

        mock_section2 = Mock()
        mock_section2.name = "__data"
        mock_section2.offset = 700
        mock_section2.size = 300

        # Create mock binary with sections
        mock_binary = Mock()
        mock_binary.header = Mock()
        mock_binary.header.sizeof = 32
        mock_binary.commands = []
        mock_binary.sections = [mock_section1, mock_section2]
        mock_binary.symbols = []
        mock_binary.libraries = []

        # Create parser and range builder
        parser = MachOParser(mock_binary)
        range_builder = RangeMappingBuilder(parser, 2048)
        range_map = range_builder.build_range_mapping()

        # Verify sections were mapped
        text_ranges = [r for r in range_map.ranges if r.tag == BinaryTag.TEXT_SEGMENT]
        data_ranges = [r for r in range_map.ranges if r.tag == BinaryTag.DATA_SEGMENT]

        assert len(text_ranges) == 1
        assert text_ranges[0].start == 100
        assert text_ranges[0].end == 600  # 100 + 500

        assert len(data_ranges) == 1
        assert data_ranges[0].start == 700
        assert data_ranges[0].end == 1000  # 700 + 300

    def test_coverage_report_structure(self) -> None:
        """Test that coverage report has the expected structure."""
        # Create a simple range map for testing
        from launchpad.models.range_mapping import RangeMap

        range_map = RangeMap(total_file_size=1000)
        range_map.add_range(0, 100, BinaryTag.HEADERS, "header")
        range_map.add_range(100, 800, BinaryTag.TEXT_SEGMENT, "text")

        # Get coverage report
        report = range_map.get_coverage_report()

        # Verify required keys are present
        required_keys = [
            "total_file_size",
            "total_mapped",
            "unmapped_size",
            "coverage_percentage",
            "conflict_count",
            "total_conflict_size",
            "unmapped_region_count",
            "largest_unmapped_region",
        ]

        for key in required_keys:
            assert key in report, f"Coverage report missing key: {key}"

        # Verify values make sense
        assert report["total_file_size"] == 1000
        assert report["total_mapped"] == 800  # 100 + 700
        assert report["unmapped_size"] == 200  # 1000 - 800
        assert report["coverage_percentage"] == 80  # 800/1000 * 100
