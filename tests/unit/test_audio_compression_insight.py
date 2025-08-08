from pathlib import Path
from unittest.mock import Mock, patch

from launchpad.size.insights.common.audio_compression import AudioCompressionInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import AudioCompressionInsightResult, FileSavingsResult
from launchpad.size.models.treemap import TreemapType


class TestAudioCompressionInsight:
    def setup_method(self):
        self.insight = AudioCompressionInsight()

    def test_generate_with_compressible_audio_files(self):
        # Create test audio files
        wav_file = FileInfo(
            full_path=Path("/tmp/audio.wav"),
            path="assets/audio.wav",
            size=1024 * 1024,  # 1MB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        aiff_file = FileInfo(
            full_path=Path("/tmp/audio.aiff"),
            path="assets/audio.aiff",
            size=2 * 1024 * 1024,  # 2MB
            file_type="aiff",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[wav_file, aiff_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        # Mock the compression analysis
        with patch.object(self.insight, "_analyze_audio_compression") as mock_analyze:
            mock_analyze.side_effect = [
                FileSavingsResult(
                    file_path="assets/audio.wav",
                    total_savings=512 * 1024,
                ),
                FileSavingsResult(
                    file_path="assets/audio.aiff",
                    total_savings=1 * 1024 * 1024,
                ),
            ]

            result = self.insight.generate(insights_input)

        assert isinstance(result, AudioCompressionInsightResult)
        assert len(result.files) == 2

        # Should be sorted by total savings (largest first)
        assert result.files[0].file_path == "assets/audio.aiff"
        assert result.files[0].total_savings == 1 * 1024 * 1024
        assert result.files[1].file_path == "assets/audio.wav"
        assert result.files[1].total_savings == 512 * 1024

        # Total savings
        expected_total = (1 * 1024 * 1024) + (512 * 1024)
        assert result.total_savings == expected_total

    def test_generate_with_no_compressible_files(self):
        # Test with non-audio files
        image_file = FileInfo(
            full_path=Path("/tmp/image.png"),
            path="assets/image.png",
            size=1024 * 1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[image_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)
        assert result is None

    def test_generate_with_small_audio_files_below_threshold(self):
        # Test with audio files too small to compress
        small_wav = FileInfo(
            full_path=Path("/tmp/small.wav"),
            path="assets/small.wav",
            size=1024,  # 1KB - below 8KB threshold
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[small_wav], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)
        assert result is None

    def test_generate_with_already_compressed_files(self):
        # Test with M4A files that are already compressed
        m4a_file = FileInfo(
            full_path=Path("/tmp/audio.m4a"),
            path="assets/audio.m4a",
            size=1024 * 1024,
            file_type="m4a",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[m4a_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)
        assert result is None

    def test_generate_with_savings_below_threshold(self):
        # Test files with savings below minimum threshold are filtered out
        wav_file = FileInfo(
            full_path=Path("/tmp/audio.wav"),
            path="assets/audio.wav",
            size=100 * 1024,  # 100KB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[wav_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        with patch.object(self.insight, "_analyze_audio_compression") as mock_analyze:
            # Mock return value with savings below threshold
            mock_analyze.return_value = FileSavingsResult(
                file_path="assets/audio.wav",
                total_savings=2 * 1024,  # Only 2KB savings (below 4KB threshold)
            )

            result = self.insight.generate(insights_input)

        # Should return None because savings are below threshold
        assert result is None
