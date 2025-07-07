from unittest.mock import Mock

from launchpad.size.insights.common import LargeVideoFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import LargeVideoFileInsightResult
from launchpad.size.models.treemap import TreemapType


class TestLargeVideoFileInsight:
    def setup_method(self):
        self.insight = LargeVideoFileInsight()

    def test_generate_with_large_files(self):
        large_video_1 = FileInfo(
            path="assets/large_video.mp4",
            absolute_path="assets/large_video.mp4",
            size=25 * 1024 * 1024,  # 25MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        large_video_2 = FileInfo(
            path="assets/large_video.mov",
            absolute_path="assets/large_video.mov",
            size=18 * 1024 * 1024,  # 18MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        small_video = FileInfo(
            path="assets/small_video.mp4",
            absolute_path="assets/small_video.mp4",
            size=5 * 1024 * 1024,  # 5MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )
        image_file = FileInfo(
            path="assets/large_image.png",
            absolute_path="assets/large_image.png",
            size=15 * 1024 * 1024,  # 15MB (should be ignored)
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash4",
        )

        file_analysis = FileAnalysis(files=[large_video_1, large_video_2, small_video, image_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 2

        # Should be sorted by largest first
        assert result.files[0].path == "assets/large_video.mp4"
        assert result.files[0].size == 25 * 1024 * 1024
        assert result.files[1].path == "assets/large_video.mov"
        assert result.files[1].size == 18 * 1024 * 1024

        # Check total savings calculation (50% of each file)
        expected_savings = (25 * 1024 * 1024 // 2) + (18 * 1024 * 1024 // 2)
        assert result.total_savings == expected_savings

    def test_generate_with_no_large_files(self):
        small_video_1 = FileInfo(
            path="assets/small_video1.mp4",
            absolute_path="assets/small_video1.mp4",
            size=5 * 1024 * 1024,  # 5MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        small_video_2 = FileInfo(
            path="assets/small_video2.mov",
            absolute_path="assets/small_video2.mov",
            size=8 * 1024 * 1024,  # 8MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[small_video_1, small_video_2])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_empty_file_list(self):
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_exactly_threshold_size(self):
        threshold_file = FileInfo(
            path="assets/threshold_video.mp4",
            absolute_path="assets/threshold_video.mp4",
            size=10 * 1024 * 1024,  # Exactly 10MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[threshold_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 0  # Should not include files exactly at threshold
        assert result.total_savings == 0

    def test_generate_with_different_video_formats(self):
        mp4_file = FileInfo(
            path="assets/video.mp4",
            absolute_path="assets/video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        mov_file = FileInfo(
            path="assets/video.mov",
            absolute_path="assets/video.mov",
            size=12 * 1024 * 1024,  # 12MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        webm_file = FileInfo(
            path="assets/video.webm",
            absolute_path="assets/video.webm",
            size=20 * 1024 * 1024,  # 20MB
            file_type="webm",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )
        mkv_file = FileInfo(
            path="assets/video.mkv",
            absolute_path="assets/video.mkv",
            size=8 * 1024 * 1024,  # 8MB (below threshold)
            file_type="mkv",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash4",
        )

        file_analysis = FileAnalysis(files=[mp4_file, mov_file, webm_file, mkv_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 3

        # Should be sorted by largest first
        assert result.files[0].path == "assets/video.webm"
        assert result.files[1].path == "assets/video.mp4"
        assert result.files[2].path == "assets/video.mov"

        # Check total savings calculation
        expected_savings = (20 * 1024 * 1024 // 2) + (15 * 1024 * 1024 // 2) + (12 * 1024 * 1024 // 2)
        assert result.total_savings == expected_savings

    def test_generate_ignores_non_video_files(self):
        video_file = FileInfo(
            path="assets/video.mp4",
            absolute_path="assets/video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        image_file = FileInfo(
            path="assets/image.png",
            absolute_path="assets/image.png",
            size=20 * 1024 * 1024,  # 20MB (should be ignored)
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        text_file = FileInfo(
            path="assets/data.txt",
            absolute_path="assets/data.txt",
            size=25 * 1024 * 1024,  # 25MB (should be ignored)
            file_type="txt",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )

        file_analysis = FileAnalysis(files=[video_file, image_file, text_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            image_map={},
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 1
        assert result.files[0].path == "assets/video.mp4"
        assert result.total_savings == 15 * 1024 * 1024 // 2
