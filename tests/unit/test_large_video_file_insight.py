from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.common.large_videos import LargeVideoFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import LargeVideoFileInsightResult
from launchpad.size.models.treemap import TreemapType


class TestLargeVideoFileInsight:
    def setup_method(self):
        self.insight = LargeVideoFileInsight()

    def test_generate_with_large_files(self):
        large_video_1 = FileInfo(
            full_path=Path("assets/large_video.mp4"),
            path="assets/large_video.mp4",
            size=25 * 1024 * 1024,  # 25MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )
        large_video_2 = FileInfo(
            full_path=Path("assets/large_video.mov"),
            path="assets/large_video.mov",
            size=18 * 1024 * 1024,  # 18MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )
        small_video = FileInfo(
            full_path=Path("assets/small_video.mp4"),
            path="assets/small_video.mp4",
            size=5 * 1024 * 1024,  # 5MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )
        image_file = FileInfo(
            full_path=Path("assets/large_image.png"),
            path="assets/large_image.png",
            size=15 * 1024 * 1024,  # 15MB (should be ignored)
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash4",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[large_video_1, large_video_2, small_video, image_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 2

        # Should be sorted by largest first
        assert result.files[0].file_path == "assets/large_video.mp4"
        assert result.files[0].total_savings == 25 * 1024 * 1024 // 2  # 50% optimization
        assert result.files[1].file_path == "assets/large_video.mov"
        assert result.files[1].total_savings == 18 * 1024 * 1024 // 2  # 50% optimization

        # Check total savings calculation (50% of file sizes)
        expected_savings = (25 * 1024 * 1024 // 2) + (18 * 1024 * 1024 // 2)
        assert result.total_savings == expected_savings

    def test_generate_with_no_large_files(self):
        small_video_1 = FileInfo(
            full_path=Path("assets/small_video1.mp4"),
            path="assets/small_video1.mp4",
            size=5 * 1024 * 1024,  # 5MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )
        small_video_2 = FileInfo(
            full_path=Path("assets/small_video2.mov"),
            path="assets/small_video2.mov",
            size=8 * 1024 * 1024,  # 8MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[small_video_1, small_video_2], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_empty_file_list(self):
        file_analysis = FileAnalysis(files=[], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_exactly_threshold_size(self):
        threshold_file = FileInfo(
            full_path=Path("assets/threshold_video.mp4"),
            path="assets/threshold_video.mp4",
            size=10 * 1024 * 1024,  # Exactly 10MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[threshold_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_different_video_formats(self):
        mp4_file = FileInfo(
            full_path=Path("assets/video.mp4"),
            path="assets/video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )
        mov_file = FileInfo(
            full_path=Path("assets/video.mov"),
            path="assets/video.mov",
            size=12 * 1024 * 1024,  # 12MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )
        webm_file = FileInfo(
            full_path=Path("assets/video.webm"),
            path="assets/video.webm",
            size=20 * 1024 * 1024,  # 20MB
            file_type="webm",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )
        mkv_file = FileInfo(
            full_path=Path("assets/video.mkv"),
            path="assets/video.mkv",
            size=8 * 1024 * 1024,  # 8MB (below threshold)
            file_type="mkv",
            treemap_type=TreemapType.ASSETS,
            hash="hash4",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[mp4_file, mov_file, webm_file, mkv_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 3

        # Should be sorted by largest first
        assert result.files[0].file_path == "assets/video.webm"
        assert result.files[1].file_path == "assets/video.mp4"
        assert result.files[2].file_path == "assets/video.mov"

        # Check total savings calculation (50% of file sizes)
        expected_savings = (20 * 1024 * 1024 // 2) + (15 * 1024 * 1024 // 2) + (12 * 1024 * 1024 // 2)
        assert result.total_savings == expected_savings

    def test_generate_ignores_non_video_files(self):
        video_file = FileInfo(
            full_path=Path("assets/video.mp4"),
            path="assets/video.mp4",
            size=15 * 1024 * 1024,  # 15MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )
        image_file = FileInfo(
            full_path=Path("assets/image.png"),
            path="assets/image.png",
            size=20 * 1024 * 1024,  # 20MB (should be ignored)
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )
        text_file = FileInfo(
            full_path=Path("assets/data.txt"),
            path="assets/data.txt",
            size=25 * 1024 * 1024,  # 25MB (should be ignored)
            file_type="txt",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[video_file, image_file, text_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeVideoFileInsightResult)
        assert len(result.files) == 1
        assert result.files[0].file_path == "assets/video.mp4"
        assert result.total_savings == 15 * 1024 * 1024 // 2  # 50% optimization
