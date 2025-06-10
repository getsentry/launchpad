"""Unit tests for the range mapping system."""

import pytest
from app_size_analyzer.models.range_mapping import BinaryTag, Range, RangeConflict, RangeMap


class TestRange:
    """Test the Range class."""

    def test_range_creation(self):
        """Test creating a range."""
        range_obj = Range(100, 200, BinaryTag.TEXT_SEGMENT, "test_section")
        assert range_obj.start == 100
        assert range_obj.end == 200
        assert range_obj.tag == BinaryTag.TEXT_SEGMENT
        assert range_obj.description == "test_section"
        assert range_obj.size == 100

    def test_range_validation(self):
        """Test range validation."""
        # Valid range
        Range(0, 100, BinaryTag.HEADERS)

        # Invalid ranges
        with pytest.raises(ValueError):
            Range(-1, 100, BinaryTag.HEADERS)  # Negative start

        with pytest.raises(ValueError):
            Range(100, 100, BinaryTag.HEADERS)  # End equals start

        with pytest.raises(ValueError):
            Range(100, 50, BinaryTag.HEADERS)  # End before start

    def test_range_overlaps(self):
        """Test range overlap detection."""
        range1 = Range(100, 200, BinaryTag.TEXT_SEGMENT)
        range2 = Range(150, 250, BinaryTag.DATA_SEGMENT)
        range3 = Range(300, 400, BinaryTag.HEADERS)

        # Overlapping ranges
        assert range1.overlaps(range2)
        assert range2.overlaps(range1)

        # Non-overlapping ranges
        assert not range1.overlaps(range3)
        assert not range3.overlaps(range1)

    def test_range_contains(self):
        """Test range contains method."""
        range_obj = Range(100, 200, BinaryTag.TEXT_SEGMENT)

        assert range_obj.contains(100)  # Start boundary
        assert range_obj.contains(150)  # Middle
        assert range_obj.contains(199)  # Just before end
        assert not range_obj.contains(99)  # Before start
        assert not range_obj.contains(200)  # End boundary (exclusive)
        assert not range_obj.contains(201)  # After end


class TestRangeConflict:
    """Test the RangeConflict class."""

    def test_conflict_creation(self):
        """Test creating a conflict from overlapping ranges."""
        range1 = Range(100, 200, BinaryTag.TEXT_SEGMENT, "range1")
        range2 = Range(150, 250, BinaryTag.DATA_SEGMENT, "range2")

        conflict = RangeConflict.from_ranges(range1, range2)
        assert conflict is not None
        assert conflict.range1 == range1
        assert conflict.range2 == range2
        assert conflict.overlap_start == 150
        assert conflict.overlap_end == 200
        assert conflict.overlap_size == 50

    def test_no_conflict_for_non_overlapping(self):
        """Test that non-overlapping ranges don't create conflicts."""
        range1 = Range(100, 200, BinaryTag.TEXT_SEGMENT)
        range2 = Range(300, 400, BinaryTag.DATA_SEGMENT)

        conflict = RangeConflict.from_ranges(range1, range2)
        assert conflict is None


class TestRangeMap:
    """Test the RangeMap class."""

    def test_range_map_creation(self):
        """Test creating a range map."""
        range_map = RangeMap(total_file_size=1000)
        assert range_map.total_file_size == 1000
        assert len(range_map.ranges) == 0
        assert len(range_map.conflicts) == 0
        assert range_map.total_mapped == 0
        assert range_map.unmapped_size == 1000

    def test_add_range(self):
        """Test adding ranges to the map."""
        range_map = RangeMap(total_file_size=1000)

        # Add a valid range
        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT, "text_section")

        assert len(range_map.ranges) == 1
        assert range_map.total_mapped == 100
        assert range_map.unmapped_size == 900

    def test_add_range_validation(self):
        """Test range validation when adding."""
        range_map = RangeMap(total_file_size=1000)

        # Range exceeding file size
        with pytest.raises(ValueError):
            range_map.add_range(900, 1100, BinaryTag.TEXT_SEGMENT)

        # Invalid range
        with pytest.raises(ValueError):
            range_map.add_range(200, 100, BinaryTag.TEXT_SEGMENT)

    def test_conflict_detection(self):
        """Test conflict detection when adding overlapping ranges."""
        range_map = RangeMap(total_file_size=1000)

        # Add first range
        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT, "text1")
        assert len(range_map.conflicts) == 0

        # Add overlapping range
        range_map.add_range(150, 250, BinaryTag.DATA_SEGMENT, "data1")
        assert len(range_map.conflicts) == 1

        conflict = range_map.conflicts[0]
        assert conflict.overlap_start == 150
        assert conflict.overlap_end == 200
        assert conflict.overlap_size == 50

    def test_unmapped_regions(self):
        """Test unmapped region detection."""
        range_map = RangeMap(total_file_size=1000)

        # Add some ranges with gaps
        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT)
        range_map.add_range(300, 400, BinaryTag.DATA_SEGMENT)
        range_map.add_range(600, 800, BinaryTag.HEADERS)

        unmapped = range_map.get_unmapped_regions()

        # Should have 4 unmapped regions:
        # 0-100, 200-300, 400-600, 800-1000
        assert len(unmapped) == 4

        assert unmapped[0].start == 0 and unmapped[0].end == 100
        assert unmapped[1].start == 200 and unmapped[1].end == 300
        assert unmapped[2].start == 400 and unmapped[2].end == 600
        assert unmapped[3].start == 800 and unmapped[3].end == 1000

    def test_size_by_tag(self):
        """Test size calculation by tag."""
        range_map = RangeMap(total_file_size=1000)

        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT)  # 100 bytes
        range_map.add_range(300, 450, BinaryTag.TEXT_SEGMENT)  # 150 bytes
        range_map.add_range(500, 600, BinaryTag.DATA_SEGMENT)  # 100 bytes

        sizes = range_map.size_by_tag()

        assert sizes[BinaryTag.TEXT_SEGMENT] == 250  # 100 + 150
        assert sizes[BinaryTag.DATA_SEGMENT] == 100
        assert sizes.get(BinaryTag.HEADERS, 0) == 0  # Not present

    def test_coverage_validation(self):
        """Test coverage validation."""
        range_map = RangeMap(total_file_size=1000)

        # Poor coverage - large unmapped region
        range_map.add_range(0, 100, BinaryTag.HEADERS)
        assert not range_map.validate_coverage(allow_unmapped_threshold=500)

        # Good coverage - small unmapped regions
        range_map.add_range(100, 990, BinaryTag.TEXT_SEGMENT)
        assert range_map.validate_coverage(allow_unmapped_threshold=50)

    def test_coverage_report(self):
        """Test coverage report generation."""
        range_map = RangeMap(total_file_size=1000)

        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT)
        range_map.add_range(300, 450, BinaryTag.DATA_SEGMENT)

        report = range_map.get_coverage_report()

        assert report["total_file_size"] == 1000
        assert report["total_mapped"] == 250  # 100 + 150
        assert report["unmapped_size"] == 750
        assert report["coverage_percentage"] == 25  # 250/1000 * 100
        assert report["conflict_count"] == 0
        assert report["unmapped_region_count"] == 3  # Before, between, after

    def test_find_ranges_at_offset(self):
        """Test finding ranges at a specific offset."""
        range_map = RangeMap(total_file_size=1000)

        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT, "text1")
        range_map.add_range(150, 250, BinaryTag.DATA_SEGMENT, "data1")  # Overlaps

        # Find ranges at offset 175 (should be in both ranges)
        ranges = range_map.find_ranges_at_offset(175)
        assert len(ranges) == 2

        # Find ranges at offset 50 (should be empty)
        ranges = range_map.find_ranges_at_offset(50)
        assert len(ranges) == 0

    def test_find_ranges_in_interval(self):
        """Test finding ranges in an interval."""
        range_map = RangeMap(total_file_size=1000)

        range_map.add_range(100, 200, BinaryTag.TEXT_SEGMENT)
        range_map.add_range(300, 400, BinaryTag.DATA_SEGMENT)
        range_map.add_range(500, 600, BinaryTag.HEADERS)

        # Find ranges in interval 150-350 (should overlap with first two)
        ranges = range_map.find_ranges_in_interval(150, 350)
        assert len(ranges) == 2

        # Find ranges in interval 700-800 (should be empty)
        ranges = range_map.find_ranges_in_interval(700, 800)
        assert len(ranges) == 0


class TestBinaryTag:
    """Test the BinaryTag enum."""

    def test_binary_tag_values(self):
        """Test that all expected binary tags exist."""
        expected_tags = [
            "cfstrings",
            "swift_file_paths",
            "method_signatures",
            "objc_type_strings",
            "c_strings",
            "headers",
            "load_commands",
            "text_segment",
            "function_starts",
            "external_methods",
            "code_signature",
            "dyld_rebase",
            "dyld_bind",
            "dyld_lazy_bind",
            "dyld_exports",
            "dyld_fixups",
            "objc_classes",
            "swift_metadata",
            "binary_modules",
            "data_segment",
            "const_data",
            "unwind_info",
            "debug_info",
            "unmapped",
        ]

        for tag_value in expected_tags:
            # This will raise an exception if the tag doesn't exist
            tag = BinaryTag(tag_value)
            assert tag.value == tag_value
