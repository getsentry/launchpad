from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from launchpad.size.insights.common.video_compression import VideoCompressionInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import VideoCompressionFileSavingsResult, VideoCompressionInsightResult
from launchpad.size.models.treemap import TreemapType


class TestVideoCompressionInsight:
    def setup_method(self):
        self.insight = VideoCompressionInsight()

    def test_generate_with_compressible_video_files(self):
        # Create test video files
        mov_file = FileInfo(
            full_path=Path("/tmp/video.mov"),
            path="assets/video.mov",
            size=10 * 1024 * 1024,  # 10MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        mp4_file = FileInfo(
            full_path=Path("/tmp/video.mp4"),
            path="assets/video.mp4",
            size=20 * 1024 * 1024,  # 20MB
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[mov_file, mp4_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        # Mock the compression analysis
        with patch.object(self.insight, "_analyze_video_compression") as mock_analyze:
            mock_analyze.side_effect = [
                VideoCompressionFileSavingsResult(
                    file_path="assets/video.mov",
                    total_savings=3 * 1024 * 1024,
                    recommended_codec="hevc",
                ),
                VideoCompressionFileSavingsResult(
                    file_path="assets/video.mp4",
                    total_savings=5 * 1024 * 1024,
                    recommended_codec="h264",
                ),
            ]

            result = self.insight.generate(insights_input)

        assert isinstance(result, VideoCompressionInsightResult)
        assert len(result.files) == 2

        # Should be sorted by total savings (largest first)
        assert result.files[0].file_path == "assets/video.mp4"
        assert result.files[0].total_savings == 5 * 1024 * 1024
        assert result.files[1].file_path == "assets/video.mov"
        assert result.files[1].total_savings == 3 * 1024 * 1024

        # Total savings
        expected_total = (5 * 1024 * 1024) + (3 * 1024 * 1024)
        assert result.total_savings == expected_total

    def test_generate_with_no_compressible_files(self):
        # Test with non-video files
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

    def test_generate_with_small_video_files_below_threshold(self):
        # Test with video files too small to compress
        small_mov = FileInfo(
            full_path=Path("/tmp/small.mov"),
            path="assets/small.mov",
            size=1024,  # 1KB - below threshold
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[small_mov], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)
        assert result is None

    def test_analyze_video_compression_success(self):
        file_info = FileInfo(
            full_path=Path("/tmp/test.mov"),
            path="assets/test.mov",
            size=10 * 1024 * 1024,  # 10MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        with patch.object(self.insight, "_get_video_bitrate") as mock_bitrate:
            with patch.object(self.insight, "_get_compressed_size") as mock_compress:
                mock_bitrate.return_value = 1000000  # 1Mbps
                # Mock H.264 compression returning better result than HEVC
                mock_compress.side_effect = [
                    7 * 1024 * 1024,  # H.264 result: 7MB
                    8 * 1024 * 1024,  # HEVC result: 8MB
                ]

                result = self.insight._analyze_video_compression(file_info)

                assert result is not None
                assert isinstance(result, VideoCompressionFileSavingsResult)
                assert result.file_path == "assets/test.mov"
                assert result.total_savings == 3 * 1024 * 1024

    def test_analyze_video_compression_no_bitrate(self):
        file_info = FileInfo(
            full_path=Path("/tmp/test.mov"),
            path="assets/test.mov",
            size=10 * 1024 * 1024,  # 10MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        with patch.object(self.insight, "_get_video_bitrate") as mock_bitrate:
            mock_bitrate.return_value = None  # No bitrate available

            result = self.insight._analyze_video_compression(file_info)
            assert result is None

    def test_analyze_video_compression_no_savings(self):
        file_info = FileInfo(
            full_path=Path("/tmp/test.mov"),
            path="assets/test.mov",
            size=10 * 1024 * 1024,  # 10MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        with patch.object(self.insight, "_get_video_bitrate") as mock_bitrate:
            with patch.object(self.insight, "_get_compressed_size") as mock_compress:
                mock_bitrate.return_value = 1000000  # 1Mbps
                # Mock compression resulting in larger files (no savings)
                mock_compress.side_effect = [
                    12 * 1024 * 1024,  # H.264 result: 12MB (larger than original)
                    11 * 1024 * 1024,  # HEVC result: 11MB (larger than original)
                ]

                result = self.insight._analyze_video_compression(file_info)
                assert result is None

    def test_analyze_video_compression_file_without_full_path(self):
        file_info = FileInfo(
            full_path=None,
            path="assets/test.mov",
            size=10 * 1024 * 1024,
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        result = self.insight._analyze_video_compression(file_info)
        assert result is None

    @patch("subprocess.run")
    def test_get_video_bitrate_success(self, mock_subprocess):
        # Mock successful ffprobe result
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1000000\n"  # 1Mbps
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        result = self.insight._get_video_bitrate(Path("/tmp/test.mov"))
        assert result == 1000000

        # Verify ffprobe was called with correct arguments
        assert mock_subprocess.called
        call_args = mock_subprocess.call_args[0][0]
        assert call_args[0] == "ffprobe"
        assert "-v" in call_args and "quiet" in call_args
        assert "-show_entries" in call_args and "stream=bit_rate" in call_args

    @patch("subprocess.run")
    def test_get_video_bitrate_failure(self, mock_subprocess):
        # Mock failed ffprobe result
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "ffprobe: error reading file"
        mock_subprocess.return_value = mock_result

        result = self.insight._get_video_bitrate(Path("/tmp/test.mov"))
        assert result is None

    @patch("subprocess.run")
    def test_get_video_bitrate_no_data(self, mock_subprocess):
        # Mock ffprobe returning N/A (no bitrate info)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "N/A\n"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        result = self.insight._get_video_bitrate(Path("/tmp/test.mov"))
        assert result is None

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_get_compressed_size_success_h264(self, mock_tempfile, mock_subprocess):
        # Mock temporary file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test-compressed.mp4"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        # Mock successful subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        # Mock the Path creation and methods to simulate file existence and size
        with patch("launchpad.size.insights.common.video_compression.Path") as mock_path_constructor:
            mock_temp_path_instance = MagicMock()
            mock_temp_path_instance.exists.return_value = True
            mock_temp_path_instance.stat.return_value.st_size = 7 * 1024 * 1024  # 7MB
            mock_temp_path_instance.__str__.return_value = "/tmp/test-compressed.mp4"
            mock_path_constructor.return_value = mock_temp_path_instance

            result = self.insight._get_compressed_size(Path("/tmp/test.mov"), "h264", 850000)

            assert result == 7 * 1024 * 1024

            # Verify ffmpeg was called with correct arguments for H.264
            assert mock_subprocess.called
            call_args = mock_subprocess.call_args[0][0]
            assert call_args[0] == "ffmpeg"
            assert "-c:v" in call_args and "libx264" in call_args
            assert "-b:v" in call_args and "850000" in call_args

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_get_compressed_size_success_hevc(self, mock_tempfile, mock_subprocess):
        # Mock temporary file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test-compressed.mov"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        # Mock successful subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        # Mock the Path creation and methods to simulate file existence and size
        with patch("launchpad.size.insights.common.video_compression.Path") as mock_path_constructor:
            mock_temp_path_instance = MagicMock()
            mock_temp_path_instance.exists.return_value = True
            mock_temp_path_instance.stat.return_value.st_size = 6 * 1024 * 1024  # 6MB
            mock_temp_path_instance.__str__.return_value = "/tmp/test-compressed.mov"
            mock_path_constructor.return_value = mock_temp_path_instance

            result = self.insight._get_compressed_size(Path("/tmp/test.mov"), "hevc", 850000)

            assert result == 6 * 1024 * 1024

            # Verify ffmpeg was called with correct arguments for HEVC
            assert mock_subprocess.called
            call_args = mock_subprocess.call_args[0][0]
            assert call_args[0] == "ffmpeg"
            assert "-c:v" in call_args and "libx265" in call_args
            assert "-b:v" in call_args and "850000" in call_args

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_get_compressed_size_failure(self, mock_tempfile, mock_subprocess):
        # Mock temporary file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test-compressed.mp4"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        # Mock failed subprocess
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "ffmpeg: error encoding video"
        mock_subprocess.return_value = mock_result

        result = self.insight._get_compressed_size(Path("/tmp/test.mov"), "h264", 850000)
        assert result is None

    @patch("subprocess.run")
    def test_get_compressed_size_tool_not_found(self, mock_subprocess):
        # Mock FileNotFoundError (ffmpeg not available)
        mock_subprocess.side_effect = FileNotFoundError("ffmpeg not found")

        result = self.insight._get_compressed_size(Path("/tmp/test.mov"), "h264", 850000)
        assert result is None

    def test_is_compressible_video_file_various_formats(self):
        # Test compressible formats
        compressible_formats = ["mov", "mp4", "m4v", "avi", "wmv", "3gp", "3g2", "mkv", "webm"]

        for fmt in compressible_formats:
            file_info = FileInfo(
                full_path=Path(f"/tmp/test.{fmt}"),
                path=f"assets/test.{fmt}",
                size=1024 * 1024,  # 1MB - above threshold
                file_type=fmt,
                treemap_type=TreemapType.ASSETS,
                hash="hash1",
                is_dir=False,
            )
            assert self.insight._is_compressible_video_file(file_info), f"Format {fmt} should be compressible"

    def test_is_compressible_video_file_non_video_formats(self):
        # Test non-video formats
        non_video_formats = ["png", "jpg", "gif", "wav", "mp3", "txt", "json"]

        for fmt in non_video_formats:
            file_info = FileInfo(
                full_path=Path(f"/tmp/test.{fmt}"),
                path=f"assets/test.{fmt}",
                size=1024 * 1024,
                file_type=fmt,
                treemap_type=TreemapType.ASSETS,
                hash="hash1",
                is_dir=False,
            )
            assert not self.insight._is_compressible_video_file(file_info), f"Format {fmt} should not be compressible"

    def test_is_compressible_video_file_too_small(self):
        # Test files below size threshold are skipped
        small_mov = FileInfo(
            full_path=Path("/tmp/small.mov"),
            path="assets/small.mov",
            size=1024,  # 1KB - below 40KB threshold
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        assert not self.insight._is_compressible_video_file(small_mov)

    def test_iter_compressible_files(self):
        # Create test files with mix of compressible and non-compressible
        mov_file = FileInfo(
            full_path=Path("/tmp/video.mov"),
            path="assets/video.mov",
            size=1024 * 1024,  # Above threshold
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        png_file = FileInfo(
            full_path=Path("/tmp/image.png"),
            path="assets/image.png",
            size=1024 * 1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash2",
            is_dir=False,
        )

        small_video = FileInfo(
            full_path=Path("/tmp/small.mp4"),
            path="assets/small.mp4",
            size=1024,  # Below threshold
            file_type="mp4",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )

        files = [mov_file, png_file, small_video]
        compressible_files = [fi for fi in files if self.insight._is_compressible_video_file(fi)]

        # Only the MOV file should be compressible
        assert len(compressible_files) == 1
        assert compressible_files[0] == mov_file

    def test_generate_with_savings_below_threshold(self):
        # Test files with savings below minimum threshold are filtered out
        mov_file = FileInfo(
            full_path=Path("/tmp/video.mov"),
            path="assets/video.mov",
            size=10 * 1024 * 1024,  # 10MB
            file_type="mov",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[mov_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        with patch.object(self.insight, "_analyze_video_compression") as mock_analyze:
            # Mock return value with savings below threshold
            mock_analyze.return_value = VideoCompressionFileSavingsResult(
                file_path="assets/video.mov",
                total_savings=2048,  # Only 2KB savings (below 4KB threshold)
                recommended_codec="h264",
            )

            result = self.insight.generate(insights_input)

        # Should return None because savings are below threshold
        assert result is None
