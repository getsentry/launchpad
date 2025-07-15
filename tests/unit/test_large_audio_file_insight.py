from unittest.mock import Mock

from launchpad.size.insights.common.large_audios import LargeAudioFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import LargeAudioFileInsightResult
from launchpad.size.models.treemap import TreemapType


class TestLargeAudioFileInsight:
    def setup_method(self):
        self.insight = LargeAudioFileInsight()

    def test_generate_with_large_audio_files(self):
        large_audio_1 = FileInfo(
            full_path="assets/large_audio.mp3",
            path="assets/large_audio.mp3",
            size=8 * 1024 * 1024,  # 8MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        large_audio_2 = FileInfo(
            full_path="assets/large_wav.wav",
            path="assets/large_wav.wav",
            size=6 * 1024 * 1024,  # 6MB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        small_audio = FileInfo(
            full_path="assets/small_audio.mp3",
            path="assets/small_audio.mp3",
            size=3 * 1024 * 1024,  # 3MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )

        file_analysis = FileAnalysis(files=[large_audio_1, large_audio_2, small_audio])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 2

        # Should be sorted by size (largest first)
        assert result.files[0].path == "assets/large_audio.mp3"
        assert result.files[0].size == 8 * 1024 * 1024
        assert result.files[1].path == "assets/large_wav.wav"
        assert result.files[1].size == 6 * 1024 * 1024

        # Total savings should be 50% of the large files
        expected_savings = (8 * 1024 * 1024 + 6 * 1024 * 1024) // 2
        assert result.total_savings == expected_savings

    def test_generate_with_no_large_audio_files(self):
        small_audio_1 = FileInfo(
            full_path="assets/small_audio1.mp3",
            path="assets/small_audio1.mp3",
            size=3 * 1024 * 1024,  # 3MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        small_audio_2 = FileInfo(
            full_path="assets/small_audio2.aac",
            path="assets/small_audio2.aac",
            size=4 * 1024 * 1024,  # 4MB
            file_type="aac",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[small_audio_1, small_audio_2])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_empty_file_list(self):
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_exactly_threshold_size(self):
        threshold_audio = FileInfo(
            full_path="assets/threshold_audio.mp3",
            path="assets/threshold_audio.mp3",
            size=5 * 1024 * 1024,  # Exactly 5MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[threshold_audio])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 0  # Should not include files exactly at threshold
        assert result.total_savings == 0

    def test_generate_with_mixed_file_types(self):
        large_audio = FileInfo(
            full_path="assets/large_audio.mp3",
            path="assets/large_audio.mp3",
            size=8 * 1024 * 1024,  # 8MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        large_image = FileInfo(
            full_path="assets/large_image.png",
            path="assets/large_image.png",
            size=15 * 1024 * 1024,  # 15MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        small_audio = FileInfo(
            full_path="assets/small_audio.wav",
            path="assets/small_audio.wav",
            size=3 * 1024 * 1024,  # 3MB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )

        file_analysis = FileAnalysis(files=[large_audio, large_image, small_audio])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 1
        assert result.files[0].path == "assets/large_audio.mp3"
        assert result.files[0].size == 8 * 1024 * 1024

        # Total savings should be 50% of the large audio file only
        expected_savings = (8 * 1024 * 1024) // 2
        assert result.total_savings == expected_savings

    def test_generate_with_various_audio_formats(self):
        mp3_file = FileInfo(
            full_path="assets/audio.mp3",
            path="assets/audio.mp3",
            size=6 * 1024 * 1024,  # 6MB
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        aac_file = FileInfo(
            full_path="assets/audio.aac",
            path="assets/audio.aac",
            size=7 * 1024 * 1024,  # 7MB
            file_type="aac",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )
        flac_file = FileInfo(
            full_path="assets/audio.flac",
            path="assets/audio.flac",
            size=9 * 1024 * 1024,  # 9MB
            file_type="flac",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )
        ogg_file = FileInfo(
            full_path="assets/audio.ogg",
            path="assets/audio.ogg",
            size=4 * 1024 * 1024,  # 4MB (below threshold)
            file_type="ogg",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash4",
        )

        file_analysis = FileAnalysis(files=[mp3_file, aac_file, flac_file, ogg_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LargeAudioFileInsightResult)
        assert len(result.files) == 3

        # Should be sorted by size (largest first)
        assert result.files[0].path == "assets/audio.flac"
        assert result.files[0].size == 9 * 1024 * 1024
        assert result.files[1].path == "assets/audio.aac"
        assert result.files[1].size == 7 * 1024 * 1024
        assert result.files[2].path == "assets/audio.mp3"
        assert result.files[2].size == 6 * 1024 * 1024

        # Total savings should be 50% of the large files
        expected_savings = (9 * 1024 * 1024 + 7 * 1024 * 1024 + 6 * 1024 * 1024) // 2
        assert result.total_savings == expected_savings
