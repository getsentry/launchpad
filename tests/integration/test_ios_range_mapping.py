"""Integration tests for iOS range mapping system."""

import json
from pathlib import Path
from typing import Any, Dict, cast

import pytest

from launchpad.analyzers.apple import AppleAppAnalyzer
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.models.range_mapping import BinaryTag


class TestIOSRangeMapping:
    """Test the iOS range mapping system against acceptance criteria."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to the sample HackerNews app."""
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    @pytest.fixture
    def legacy_baseline(self) -> Dict[str, Any]:
        """Load the legacy baseline results for comparison."""
        baseline_path = Path("tests/_fixtures/ios/hackernews-results.json")
        with open(baseline_path, "r") as f:
            data: Dict[str, Any] = json.load(f)
            return data

    def test_hackernews_range_mapping_regression(self, sample_app_path: Path) -> None:
        """Test range mapping against known HackerNews app structure to detect regressions.

        This test asserts against the specific section sizes and mappings we expect
        from the HackerNews sample app to catch any regressions in the range mapping logic.
        """
        analyzer = AppleAppAnalyzer(skip_range_mapping=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Get the first binary analysis result since we know there's only one binary
        binary_analysis = results.binary_analysis[0]
        range_map = binary_analysis.range_map
        assert range_map is not None, "Range mapping should be created"

        # Test exact file structure from HackerNews binary
        assert range_map.total_file_size == 3152944
        assert range_map.total_mapped == 3076062
        assert len(range_map.ranges) == 121

        # Test coverage report structure
        report = range_map.get_coverage_report()
        expected_coverage = {
            "total_file_size": 3152944,
            "total_mapped": 3076062,
            "unmapped_size": 76882,
            "coverage_percentage": 97,
            "conflict_count": 0,
            "total_conflict_size": 0,
            "unmapped_region_count": 14,
            "largest_unmapped_region": 39616,
        }

        for key, expected_value in expected_coverage.items():
            assert report[key] == expected_value, f"Coverage report {key} should be {expected_value}, got {report[key]}"

        # Test specific section sizes (these are the actual sizes from HackerNews binary)
        size_by_tag = range_map.size_by_tag()
        expected_sizes = {
            BinaryTag.TEXT_SEGMENT: 1842548,
            BinaryTag.OBJC_CLASSES: 430336,
            BinaryTag.DATA_SEGMENT: 114666,
            BinaryTag.C_STRINGS: 197007,
            BinaryTag.SWIFT_METADATA: 114830,
            BinaryTag.CONST_DATA: 79511,
            BinaryTag.UNMAPPED: 0,
            BinaryTag.UNWIND_INFO: 59076,
            BinaryTag.CODE_SIGNATURE: 43488,
            BinaryTag.FUNCTION_STARTS: 13584,
            BinaryTag.LOAD_COMMANDS: 8312,
            BinaryTag.HEADERS: 32,
        }

        for tag, expected_size in expected_sizes.items():
            actual_size = size_by_tag.get(tag, 0)
            assert actual_size == expected_size, f"Section {tag.name} size should be {expected_size}, got {actual_size}"

    def test_section_mapping_completeness(self, sample_app_path: Path) -> None:
        """Test that sections are properly mapped to ranges in real binary."""
        analyzer = AppleAppAnalyzer(skip_range_mapping=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Get the first binary analysis result since we know there's only one binary
        binary_analysis = results.binary_analysis[0]
        range_map = binary_analysis.range_map
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
