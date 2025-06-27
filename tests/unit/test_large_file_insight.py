"""Tests for LargeFileInsight."""

from unittest.mock import Mock

from launchpad.insights.common import LargeFileInsight
from launchpad.insights.insight import InsightsInput
from launchpad.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.models.insights import LargeFileInsightResult
from launchpad.models.treemap import TreemapType


class TestLargeFileInsight:
    """Test cases for LargeFileInsight."""

    def setup_method(self):
        """Set up test fixtures."""
        self.insight = LargeFileInsight()

    def test_generate_with_large_files(self):
        """Test insight generation with files larger than 10MB."""

        large_file_1 = FileInfo(
            path="assets/large_video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        large_file_2 = FileInfo(
            path="assets/large_image.png",
            size=12 * 1024 * 1024,  # 12MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        small_file = FileInfo(
            path="assets/small_image.png",
            size=5 * 1024 * 1024,  # 5MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )

        file_analysis = FileAnalysis(files=[large_file_1, large_file_2, small_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeFileInsightResult)
        assert len(result.files) == 2
        assert result.large_file_count == 2
        assert result.total_savings == 27 * 1024 * 1024  # 15MB + 12MB

        assert result.files[0].path == "assets/large_video.mp4"
        assert result.files[1].path == "assets/large_image.png"

    def test_generate_with_no_large_files(self):
        """Test insight generation when no files are larger than 10MB."""
        small_file_1 = FileInfo(
            path="assets/small_image1.png",
            size=5 * 1024 * 1024,  # 5MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        small_file_2 = FileInfo(
            path="assets/small_image2.png",
            size=8 * 1024 * 1024,  # 8MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[small_file_1, small_file_2])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeFileInsightResult)
        assert len(result.files) == 0
        assert result.large_file_count == 0
        assert result.total_savings == 0

    def test_generate_with_empty_file_list(self):
        """Test insight generation with an empty file list."""
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeFileInsightResult)
        assert len(result.files) == 0
        assert result.large_file_count == 0
        assert result.total_savings == 0

    def test_generate_with_exactly_threshold_size(self):
        """Test insight generation with files exactly at the threshold size."""

        threshold_file = FileInfo(
            path="assets/threshold_image.png",
            size=10 * 1024 * 1024,  # Exactly 10MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[threshold_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeFileInsightResult)
        assert len(result.files) == 0  # Should not include files exactly at threshold
        assert result.large_file_count == 0
        assert result.total_savings == 0
