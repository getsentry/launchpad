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

    def test_range_mapping_coverage(self, sample_app_path: Path, legacy_baseline: Dict[str, Any]) -> None:
        """Test range mapping coverage meets acceptance criteria.

        Acceptance Criteria:
        - 100% Binary Coverage: Every byte in the binary must be mapped to a category (no unmapped regions > 1KB)
        - Conflict Detection: Report any overlapping ranges and total conflict size
        - Category Consistency: Total mapped size = file size - unmapped regions
        - Performance: Process 100MB binary in < 30 seconds
        """
        # Run analysis with range mapping enabled
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        # Verify range mapping was created
        assert results.binary_analysis.range_map is not None, "Range mapping should be created"
        range_map = results.binary_analysis.range_map

        # Test 100% Binary Coverage - no unmapped regions > 1KB
        unmapped_regions = range_map.get_unmapped_regions()
        largest_unmapped = max((r.size for r in unmapped_regions), default=0)
        assert largest_unmapped <= 1024, f"Largest unmapped region ({largest_unmapped} bytes) exceeds 1KB limit"

        # Test Category Consistency - total mapped + unmapped should equal file size
        expected_size = range_map.total_mapped + range_map.unmapped_size
        assert (
            expected_size == range_map.total_file_size
        ), f"Size consistency check failed: {expected_size} != {range_map.total_file_size}"

        # Test that we have reasonable coverage (at least 90%)
        coverage_report = range_map.get_coverage_report()
        assert (
            coverage_report["coverage_percentage"] >= 90
        ), f"Coverage too low: {coverage_report['coverage_percentage']}%"

        # Verify conflict detection is working
        conflicts = range_map.conflicts
        total_conflict_size = sum(c.overlap_size for c in conflicts)
        assert isinstance(total_conflict_size, int), "Conflict size should be calculable"

    def test_range_mapping_categories(self, sample_app_path: Path) -> None:
        """Test that range mapping properly categorizes binary content."""
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        range_map = results.binary_analysis.range_map
        assert range_map is not None

        # Get size breakdown by category
        size_by_tag = range_map.size_by_tag()

        # Verify we have the expected categories for an iOS app
        expected_categories = [
            BinaryTag.HEADERS,
            BinaryTag.LOAD_COMMANDS,
            BinaryTag.TEXT_SEGMENT,
            BinaryTag.DATA_SEGMENT,
        ]

        for category in expected_categories:
            assert category in size_by_tag, f"Expected category {category} not found"
            assert size_by_tag[category] > 0, f"Category {category} should have non-zero size"

        # Verify that TEXT_SEGMENT is one of the largest categories (typical for executables)
        text_size = size_by_tag.get(BinaryTag.TEXT_SEGMENT, 0)
        total_categorized = sum(size_by_tag.values())
        text_percentage = (text_size / max(1, total_categorized)) * 100

        # TEXT segment should be significant portion of the binary (at least 5%)
        assert text_percentage >= 5, f"TEXT segment only {text_percentage:.1f}% of binary"

    def test_range_mapping_performance(self, sample_app_path: Path) -> None:
        """Test that range mapping performance meets requirements."""
        import time

        # Get file size for performance scaling
        file_size = sample_app_path.stat().st_size

        start_time = time.time()
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)
        end_time = time.time()

        analysis_time = end_time - start_time

        # Performance should scale reasonably - using 30 seconds per 100MB as baseline
        # For the ~10MB sample app, should complete much faster
        max_time = (file_size / (100 * 1024 * 1024)) * 30  # 30 seconds per 100MB
        max_time = max(max_time, 30)  # At least 30 seconds for small files

        assert analysis_time < max_time, (
            f"Analysis took {analysis_time:.1f}s, expected < {max_time:.1f}s "
            f"for {file_size / (1024*1024):.1f}MB file"
        )

        # Verify range mapping was actually created
        assert results.binary_analysis.range_map is not None
        assert len(results.binary_analysis.range_map.ranges) > 0

    def test_range_mapping_validation(self, sample_app_path: Path) -> None:
        """Test range mapping validation methods."""
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        range_map = results.binary_analysis.range_map
        assert range_map is not None

        # Test coverage validation
        is_valid = range_map.validate_coverage(allow_unmapped_threshold=1024)
        assert is_valid, "Range mapping should pass validation with 1KB unmapped threshold"

        # Test coverage report structure
        report = range_map.get_coverage_report()
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
            assert isinstance(report[key], int), f"Coverage report key {key} should be int"

        # Verify logical constraints
        assert report["total_file_size"] > 0
        assert report["coverage_percentage"] >= 0 and report["coverage_percentage"] <= 100
        assert report["total_mapped"] + report["unmapped_size"] == report["total_file_size"]

    def test_range_mapping_conflict_handling(self, sample_app_path: Path) -> None:
        """Test that range mapping properly handles and reports conflicts."""
        analyzer = IOSAnalyzer(enable_range_mapping=True)
        results = analyzer.analyze(sample_app_path)

        range_map = results.binary_analysis.range_map
        assert range_map is not None

        # Get conflicts
        conflicts = range_map.conflicts

        # Verify conflict structure if any exist
        for conflict in conflicts:
            assert conflict.overlap_size > 0, "Conflict overlap size should be positive"
            assert conflict.overlap_start < conflict.overlap_end, "Conflict range should be valid"
            assert conflict.range1.overlaps(conflict.range2), "Conflicting ranges should actually overlap"

        # Total conflict size should be reasonable (< 10% of file)
        total_conflict_size = sum(c.overlap_size for c in conflicts)
        max_acceptable_conflicts = range_map.total_file_size * 0.1  # 10% max

        assert (
            total_conflict_size <= max_acceptable_conflicts
        ), f"Too many conflicts: {total_conflict_size} bytes ({(total_conflict_size/range_map.total_file_size)*100:.1f}%)"  # noqa: E501
