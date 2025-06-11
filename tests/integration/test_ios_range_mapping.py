"""Integration tests for iOS range mapping system."""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from launchpad.analyzers.ios import IOSAnalyzer
from launchpad.models import BinaryTag


class TestIOSRangeMapping:
    """Test the iOS range mapping system against acceptance criteria."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to the sample HackerNews app."""
        return Path(__file__).parent.parent / "artifacts" / "HackerNews.xcarchive.zip"

    @pytest.fixture
    def legacy_baseline(self) -> Dict[str, Any]:
        """Load the legacy baseline results for comparison."""
        baseline_path = Path(__file__).parent.parent / "artifacts" / "hackernews-results.json"
        with open(baseline_path, "r") as f:
            data: Dict[str, Any] = json.load(f)
            return data

    def test_hackernews_range_mapping_regression(self, sample_app_path: Path) -> None:
        """Test range mapping against known HackerNews app structure to detect regressions.

        This test asserts against the specific section sizes and mappings we expect
        from the HackerNews sample app to catch any regressions in the range mapping logic.
        """
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        range_map = results.binary_analysis.range_map
        assert range_map is not None, "Range mapping should be created"

        # Test exact file structure from HackerNews binary
        assert range_map.total_file_size == 2628128, "Total file size should match expected binary size"
        assert range_map.total_mapped == 2536160
        assert len(range_map.ranges) == 119, "Should have exactly 136 mapped ranges"

        # Test coverage report structure
        report = range_map.get_coverage_report()
        expected_coverage = {
            "total_file_size": 2628128,
            "total_mapped": 2536160,
            "unmapped_size": 91968,
            "coverage_percentage": 96,
            "conflict_count": 0,
            "total_conflict_size": 0,
            "unmapped_region_count": 18,
            "largest_unmapped_region": 36376,
        }

        for key, expected_value in expected_coverage.items():
            assert report[key] == expected_value, f"Coverage report {key} should be {expected_value}, got {report[key]}"

        # Test specific section sizes (these are the actual sizes from HackerNews binary)
        size_by_tag = range_map.size_by_tag()
        expected_sizes = {
            BinaryTag.TEXT_SEGMENT: 1507180,
            BinaryTag.OBJC_CLASSES: 371123,
            BinaryTag.DATA_SEGMENT: 102838,
            BinaryTag.C_STRINGS: 150167,
            BinaryTag.SWIFT_METADATA: 87585,
            BinaryTag.CONST_DATA: 58559,
            BinaryTag.UNMAPPED: 0,
            BinaryTag.UNWIND_INFO: 50836,
            BinaryTag.CODE_SIGNATURE: 39424,
            BinaryTag.FUNCTION_STARTS: 11000,
            BinaryTag.LOAD_COMMANDS: 8152,
            BinaryTag.HEADERS: 32,
        }

        for tag, expected_size in expected_sizes.items():
            actual_size = size_by_tag.get(tag, 0)
            assert actual_size == expected_size, f"Section {tag.name} size should be {expected_size}, got {actual_size}"

    def test_section_mapping_completeness(self, sample_app_path: Path) -> None:
        """Test that sections are properly mapped to ranges in real binary."""
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        range_map = results.binary_analysis.range_map
        assert range_map is not None

        # Verify we have both text and data ranges
        text_ranges = [r for r in range_map.ranges if r.tag == BinaryTag.TEXT_SEGMENT]
        data_ranges = [r for r in range_map.ranges if r.tag == BinaryTag.DATA_SEGMENT]

        assert len(text_ranges) >= 1, "Should have at least one TEXT segment range"
        assert len(data_ranges) >= 1, "Should have at least one DATA segment range"

        # Verify ranges are non-empty and ordered
        for range_obj in range_map.ranges:
            assert range_obj.start < range_obj.end, f"Range {range_obj} should have start < end"
            assert range_obj.size > 0, f"Range {range_obj} should have positive size"
