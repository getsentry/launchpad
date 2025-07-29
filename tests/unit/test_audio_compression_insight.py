from concurrent.futures import Future
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from launchpad.size.insights.apple.audio_compression import AudioCompressionInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import AudioCompressionInsightResult, OptimizableAudioFile
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
            # Set up mock return values
            future1 = Future()
            future1.set_result(
                OptimizableAudioFile(
                    file_path="assets/audio.wav",
                    current_size=1024 * 1024,
                    current_format="wav",
                    compressed_size=512 * 1024,
                    potential_savings=512 * 1024,
                    target_format="aac",
                    target_bitrate=128000,
                )
            )

            future2 = Future()
            future2.set_result(
                OptimizableAudioFile(
                    file_path="assets/audio.aiff",
                    current_size=2 * 1024 * 1024,
                    current_format="aiff",
                    compressed_size=1 * 1024 * 1024,
                    potential_savings=1 * 1024 * 1024,
                    target_format="aac",
                    target_bitrate=128000,
                )
            )

            mock_analyze.side_effect = [
                OptimizableAudioFile(
                    file_path="assets/audio.wav",
                    current_size=1024 * 1024,
                    current_format="wav",
                    compressed_size=512 * 1024,
                    potential_savings=512 * 1024,
                    target_format="aac",
                    target_bitrate=128000,
                ),
                OptimizableAudioFile(
                    file_path="assets/audio.aiff",
                    current_size=2 * 1024 * 1024,
                    current_format="aiff",
                    compressed_size=1 * 1024 * 1024,
                    potential_savings=1 * 1024 * 1024,
                    target_format="aac",
                    target_bitrate=128000,
                ),
            ]

            result = self.insight.generate(insights_input)

        assert isinstance(result, AudioCompressionInsightResult)
        assert len(result.optimizable_files) == 2

        # Should be sorted by potential savings (largest first)
        assert result.optimizable_files[0].file_path == "assets/audio.aiff"
        assert result.optimizable_files[0].potential_savings == 1 * 1024 * 1024
        assert result.optimizable_files[1].file_path == "assets/audio.wav"
        assert result.optimizable_files[1].potential_savings == 512 * 1024

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

    def test_analyze_audio_compression_success(self):
        file_info = FileInfo(
            full_path=Path("/tmp/test.wav"),
            path="assets/test.wav",
            size=1024 * 1024,  # 1MB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        with patch.object(self.insight, "_get_compressed_size") as mock_compress:
            mock_compress.return_value = 512 * 1024  # 512KB compressed

            result = self.insight._analyze_audio_compression(file_info)

            assert result is not None
            assert isinstance(result, OptimizableAudioFile)
            assert result.file_path == "assets/test.wav"
            assert result.current_size == 1024 * 1024
            assert result.current_format == "wav"
            assert result.compressed_size == 512 * 1024
            assert result.potential_savings == 512 * 1024
            assert result.target_format == "aac"
            assert result.target_bitrate == 128000

    def test_analyze_audio_compression_no_savings(self):
        file_info = FileInfo(
            full_path=Path("/tmp/test.wav"),
            path="assets/test.wav",
            size=1024 * 1024,  # 1MB
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        with patch.object(self.insight, "_get_compressed_size") as mock_compress:
            # Compressed size is larger than original (no savings)
            mock_compress.return_value = 2 * 1024 * 1024

            result = self.insight._analyze_audio_compression(file_info)
            assert result is None

    def test_analyze_audio_compression_file_without_full_path(self):
        file_info = FileInfo(
            full_path=None,
            path="assets/test.wav",
            size=1024 * 1024,
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        result = self.insight._analyze_audio_compression(file_info)
        assert result is None

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_get_compressed_size_success(self, mock_tempfile, mock_subprocess):
        # Mock temporary file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test-compressed.m4a"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        # Mock successful subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        # Mock the Path creation and methods to simulate file existence and size
        with patch("launchpad.size.insights.apple.audio_compression.Path") as mock_path_constructor:
            # Create a mock instance that will be returned by Path()
            mock_temp_path_instance = MagicMock()
            mock_temp_path_instance.exists.return_value = True
            mock_temp_path_instance.stat.return_value.st_size = 512 * 1024  # 512KB
            # Ensure str() returns the expected path
            mock_temp_path_instance.__str__.return_value = "/tmp/test-compressed.m4a"

            # Make Path() return our mock instance
            mock_path_constructor.return_value = mock_temp_path_instance

            result = self.insight._get_compressed_size(Path("/tmp/test.wav"))

            assert result == 512 * 1024

            # Verify subprocess was called with ffmpeg
            assert mock_subprocess.called
            call_args = mock_subprocess.call_args[0][0]  # First positional arg (the command list)
            assert call_args[0] == "ffmpeg"
            assert "-i" in call_args
            assert "-c:a" in call_args and "aac" in call_args
            assert "-b:a" in call_args and "128k" in call_args
            assert "/tmp/test.wav" in call_args

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_get_compressed_size_failure(self, mock_tempfile, mock_subprocess):
        # Mock temporary file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test-compressed.m4a"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        # Mock failed subprocess
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "ffmpeg: error: unsupported format"
        mock_subprocess.return_value = mock_result

        result = self.insight._get_compressed_size(Path("/tmp/test.wav"))
        assert result is None

    @patch("subprocess.run")
    def test_get_compressed_size_tool_not_found(self, mock_subprocess):
        # Mock FileNotFoundError (ffmpeg not available)
        mock_subprocess.side_effect = FileNotFoundError("ffmpeg not found")

        result = self.insight._get_compressed_size(Path("/tmp/test.wav"))
        assert result is None

    def test_is_compressible_audio_file_various_formats(self):
        # Test compressible formats
        compressible_formats = ["wav", "aiff", "aif", "au", "snd", "mp3", "caf", "3gp", "3g2", "amr"]

        for fmt in compressible_formats:
            file_info = FileInfo(
                full_path=Path(f"/tmp/test.{fmt}"),
                path=f"assets/test.{fmt}",
                size=100 * 1024,  # 100KB - above threshold
                file_type=fmt,
                treemap_type=TreemapType.ASSETS,
                hash="hash1",
                is_dir=False,
            )
            assert self.insight._is_compressible_audio_file(file_info), f"Format {fmt} should be compressible"

    def test_is_compressible_audio_file_non_audio_formats(self):
        # Test non-audio formats
        non_audio_formats = ["png", "jpg", "gif", "mp4", "mov", "txt", "json"]

        for fmt in non_audio_formats:
            file_info = FileInfo(
                full_path=Path(f"/tmp/test.{fmt}"),
                path=f"assets/test.{fmt}",
                size=100 * 1024,
                file_type=fmt,
                treemap_type=TreemapType.ASSETS,
                hash="hash1",
                is_dir=False,
            )
            assert not self.insight._is_compressible_audio_file(file_info), f"Format {fmt} should not be compressible"

    def test_is_compressible_audio_file_already_aac_m4a(self):
        # Test M4A files (already compressed) are skipped
        m4a_file = FileInfo(
            full_path=Path("/tmp/test.m4a"),
            path="assets/test.m4a",
            size=100 * 1024,
            file_type="m4a",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        assert not self.insight._is_compressible_audio_file(m4a_file)

    def test_is_compressible_audio_file_too_small(self):
        # Test files below size threshold are skipped
        small_wav = FileInfo(
            full_path=Path("/tmp/small.wav"),
            path="assets/small.wav",
            size=1024,  # 1KB - below 8KB threshold
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        assert not self.insight._is_compressible_audio_file(small_wav)

    def test_is_likely_aac_encoded(self):
        # Test M4A files are considered already encoded
        m4a_file = FileInfo(
            full_path=Path("/tmp/test.m4a"),
            path="assets/test.m4a",
            size=100 * 1024,
            file_type="m4a",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        assert self.insight._is_likely_aac_encoded(m4a_file)

        # Test non-M4A files are not considered encoded
        wav_file = FileInfo(
            full_path=Path("/tmp/test.wav"),
            path="assets/test.wav",
            size=100 * 1024,
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        assert not self.insight._is_likely_aac_encoded(wav_file)

    def test_iter_compressible_files(self):
        # Create test files with mix of compressible and non-compressible
        wav_file = FileInfo(
            full_path=Path("/tmp/audio.wav"),
            path="assets/audio.wav",
            size=100 * 1024,  # Above threshold
            file_type="wav",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        png_file = FileInfo(
            full_path=Path("/tmp/image.png"),
            path="assets/image.png",
            size=100 * 1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )

        small_audio = FileInfo(
            full_path=Path("/tmp/small.mp3"),
            path="assets/small.mp3",
            size=1024,  # Below threshold
            file_type="mp3",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )

        files = [wav_file, png_file, small_audio]
        compressible_files = list(self.insight._iter_compressible_files(files))

        # Only the WAV file should be compressible
        assert len(compressible_files) == 1
        assert compressible_files[0] == wav_file

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
            mock_analyze.return_value = OptimizableAudioFile(
                file_path="assets/audio.wav",
                current_size=100 * 1024,
                current_format="wav",
                compressed_size=98 * 1024,  # Only 2KB savings (below 4KB threshold)
                potential_savings=2 * 1024,
                target_format="aac",
                target_bitrate=128000,
            )

            result = self.insight.generate(insights_input)

        # Should return None because savings are below threshold
        assert result is None
