from unittest.mock import Mock

from launchpad.size.insights.common import LargeImageFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import LargeImageFileInsightResult
from launchpad.size.models.treemap import TreemapType


class TestLargeImageFileInsight:
    def setup_method(self):
        self.insight = LargeImageFileInsight()

    def test_generate_with_large_files(self):
        large_file_1 = FileInfo(
            full_path="assets/large_video.mp4",
            path="assets/large_video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        large_file_2 = FileInfo(
            full_path="assets/large_image.png",
            path="assets/large_image.png",
            size=12 * 1024 * 1024,  # 12MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        small_file = FileInfo(
            full_path="assets/small_image.png",
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

        assert isinstance(result, LargeImageFileInsightResult)
        assert len(result.files) == 1

        assert result.files[0].path == "assets/large_image.png"

    def test_generate_with_no_large_files(self):
        small_file_1 = FileInfo(
            full_path="assets/small_image1.png",
            path="assets/small_image1.png",
            size=5 * 1024 * 1024,  # 5MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        small_file_2 = FileInfo(
            full_path="assets/small_image2.png",
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

        assert isinstance(result, LargeImageFileInsightResult)
        assert len(result.files) == 0

    def test_generate_with_empty_file_list(self):
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeImageFileInsightResult)
        assert len(result.files) == 0

    def test_generate_with_exactly_threshold_size(self):
        threshold_file = FileInfo(
            full_path="assets/threshold_image.png",
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

        assert isinstance(result, LargeImageFileInsightResult)
        assert len(result.files) == 0  # Should not include files exactly at threshold
