"""Tests for the 16KB page ready insight."""

import tempfile

from pathlib import Path
from unittest.mock import Mock, patch

from launchpad.size.insights.android.sixteen_kb_page_ready import SixteenKBPageReadyInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import SixteenKBPageReadyInsightResult
from launchpad.size.models.treemap import TreemapType


class TestSixteenKBPageReadyInsight:
    def setup_method(self):
        self.insight = SixteenKBPageReadyInsight()

    def _create_insights_input(self, files: list[FileInfo]) -> InsightsInput:
        file_analysis = FileAnalysis(items=files)
        return InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=file_analysis,
            treemap=None,
            binary_analysis=[],
        )

    def _create_mock_elf_binary(self, sections_alignments: list[int]):
        """Create a mock ELF binary with sections having the specified alignments."""
        mock_binary = Mock()
        mock_sections = []

        for i, alignment in enumerate(sections_alignments):
            mock_section = Mock()
            mock_section.alignment = alignment
            mock_section.name = f"section_{i}"
            mock_sections.append(mock_section)

        mock_binary.sections = mock_sections
        return mock_binary

    def test_all_libraries_aligned_16kb_ready(self):
        """Test that app is 16KB ready when all libraries have proper alignment."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock files
            arm64_lib = Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so"
            x86_64_lib = Path(temp_dir) / "lib" / "x86_64" / "libutils.so"

            files = [
                FileInfo(
                    full_path=arm64_lib,
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
                FileInfo(
                    full_path=x86_64_lib,
                    path="lib/x86_64/libutils.so",
                    size=400000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="x86_64_utils_hash",
                    is_dir=False,
                ),
            ]

            # Mock LIEF to return properly aligned sections
            mock_binary_arm64 = self._create_mock_elf_binary([0, 16384, 32768])  # All >= 16KB
            mock_binary_x86_64 = self._create_mock_elf_binary([1, 65536, 16384])  # All >= 16KB

            with patch("lief.parse") as mock_parse:
                mock_parse.side_effect = [mock_binary_arm64, mock_binary_x86_64]

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is True
                assert result.unaligned_files == []
                assert result.total_unaligned_files == 0

    def test_some_libraries_unaligned_not_16kb_ready(self):
        """Test that app is not 16KB ready when some libraries have improper alignment."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock files
            arm64_lib = Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so"
            x86_64_lib = Path(temp_dir) / "lib" / "x86_64" / "libutils.so"

            files = [
                FileInfo(
                    full_path=arm64_lib,
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
                FileInfo(
                    full_path=x86_64_lib,
                    path="lib/x86_64/libutils.so",
                    size=400000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="x86_64_utils_hash",
                    is_dir=False,
                ),
            ]

            # Mock LIEF: arm64 properly aligned, x86_64 has alignment issues
            mock_binary_arm64 = self._create_mock_elf_binary([0, 16384, 32768])  # All >= 16KB
            mock_binary_x86_64 = self._create_mock_elf_binary([1, 8192, 16384])  # One section < 16KB

            with patch("lief.parse") as mock_parse:
                mock_parse.side_effect = [mock_binary_arm64, mock_binary_x86_64]

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is False
                assert "lib/x86_64/libutils.so" in result.unaligned_files
                assert "lib/arm64-v8a/libnative.so" not in result.unaligned_files
                assert result.total_unaligned_files == 1

    def test_only_target_architectures_checked(self):
        """Test that only arm64-v8a and x86_64 architectures are checked."""
        with tempfile.TemporaryDirectory() as temp_dir:
            files = [
                # arm64-v8a (should be checked)
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so",
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
                # x86_64 (should be checked)
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "x86_64" / "libutils.so",
                    path="lib/x86_64/libutils.so",
                    size=400000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="x86_64_utils_hash",
                    is_dir=False,
                ),
                # x86 (should NOT be checked)
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "x86" / "libother.so",
                    path="lib/x86/libother.so",
                    size=300000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="x86_other_hash",
                    is_dir=False,
                ),
                # armeabi-v7a (should NOT be checked)
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "armeabi-v7a" / "liblegacy.so",
                    path="lib/armeabi-v7a/liblegacy.so",
                    size=350000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="armv7_legacy_hash",
                    is_dir=False,
                ),
            ]

            # Mock LIEF: arm64 and x86_64 both have alignment issues
            mock_binary_with_issues = self._create_mock_elf_binary([8192])  # < 16KB

            with patch("lief.parse") as mock_parse:
                # Should only be called twice (arm64-v8a and x86_64)
                mock_parse.side_effect = [mock_binary_with_issues, mock_binary_with_issues]

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is False
                assert len(result.unaligned_files) == 2
                assert "lib/arm64-v8a/libnative.so" in result.unaligned_files
                assert "lib/x86_64/libutils.so" in result.unaligned_files
                # These should NOT be in unaligned_files
                assert "lib/x86/libother.so" not in result.unaligned_files
                assert "lib/armeabi-v7a/liblegacy.so" not in result.unaligned_files
                assert result.total_unaligned_files == 2

                # Verify LIEF parse was called exactly twice
                assert mock_parse.call_count == 2

    def test_no_native_libraries_returns_16kb_ready(self):
        """Test that apps with no native libraries are considered 16KB ready."""
        files = [
            FileInfo(
                full_path=Path("assets/image.png"),
                path="assets/image.png",
                size=50000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="image_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("classes.dex"),
                path="classes.dex",
                size=1000000,
                file_type="dex",
                treemap_type=TreemapType.DEX,
                hash="dex_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, SixteenKBPageReadyInsightResult)
        assert result.is_16kb_ready is True
        assert result.unaligned_files == []
        assert result.total_unaligned_files == 0

    def test_no_target_architecture_libraries_returns_16kb_ready(self):
        """Test that apps with only non-target architecture libraries are considered 16KB ready."""
        files = [
            FileInfo(
                full_path=Path("lib/x86/libnative.so"),
                path="lib/x86/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/armeabi-v7a/libutils.so"),
                path="lib/armeabi-v7a/libutils.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="armv7_utils_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, SixteenKBPageReadyInsightResult)
        assert result.is_16kb_ready is True
        assert result.unaligned_files == []
        assert result.total_unaligned_files == 0

    def test_elf_parsing_error_handled_gracefully(self):
        """Test that ELF parsing errors don't cause the insight to fail."""
        with tempfile.TemporaryDirectory() as temp_dir:
            files = [
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so",
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
            ]

            with patch("lief.parse") as mock_parse:
                # Simulate LIEF parsing error
                mock_parse.side_effect = Exception("Failed to parse ELF file")

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                # Should still return a result, considering the file as properly aligned
                # since we couldn't determine otherwise
                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is True
                assert result.unaligned_files == []
                assert result.total_unaligned_files == 0

    def test_lief_returns_none_handled_gracefully(self):
        """Test that LIEF returning None is handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            files = [
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so",
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
            ]

            with patch("lief.parse") as mock_parse:
                # Simulate LIEF returning None (unparseable file)
                mock_parse.return_value = None

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                # Should still return a result, considering the file as properly aligned
                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is True
                assert result.unaligned_files == []
                assert result.total_unaligned_files == 0

    def test_sections_with_zero_and_one_alignment_ignored(self):
        """Test that sections with alignment 0 or 1 are ignored."""
        with tempfile.TemporaryDirectory() as temp_dir:
            files = [
                FileInfo(
                    full_path=Path(temp_dir) / "lib" / "arm64-v8a" / "libnative.so",
                    path="lib/arm64-v8a/libnative.so",
                    size=500000,
                    file_type="so",
                    treemap_type=TreemapType.NATIVE_LIBRARIES,
                    hash="arm64_native_hash",
                    is_dir=False,
                ),
            ]

            # Mock LIEF with sections having alignments 0, 1 (should be ignored) and 8192 (< 16KB)
            mock_binary = self._create_mock_elf_binary([0, 1, 8192])

            with patch("lief.parse") as mock_parse:
                mock_parse.return_value = mock_binary

                insights_input = self._create_insights_input(files)
                result = self.insight.generate(insights_input)

                # Should detect the alignment issue from the 8192 alignment section
                assert isinstance(result, SixteenKBPageReadyInsightResult)
                assert result.is_16kb_ready is False
                assert "lib/arm64-v8a/libnative.so" in result.unaligned_files
                assert result.total_unaligned_files == 1

    def test_empty_file_list_returns_16kb_ready(self):
        """Test that empty file list returns 16KB ready."""
        insights_input = self._create_insights_input([])
        result = self.insight.generate(insights_input)

        assert isinstance(result, SixteenKBPageReadyInsightResult)
        assert result.is_16kb_ready is True
        assert result.unaligned_files == []
        assert result.total_unaligned_files == 0

    def test_malformed_lib_path_ignored(self):
        """Test that files with malformed lib paths are ignored."""
        files = [
            # Valid path
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            # Malformed paths (should be ignored)
            FileInfo(
                full_path=Path("libnative.so"),
                path="libnative.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="malformed1_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/libnative.so"),
                path="lib/libnative.so",
                size=300000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="malformed2_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("assets/lib/arm64-v8a/libnative.so"),
                path="assets/lib/arm64-v8a/libnative.so",
                size=200000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="malformed3_hash",
                is_dir=False,
            ),
        ]

        # Mock LIEF with proper alignment
        mock_binary = self._create_mock_elf_binary([16384])  # >= 16KB

        with patch("lief.parse") as mock_parse:
            mock_parse.return_value = mock_binary

            insights_input = self._create_insights_input(files)
            result = self.insight.generate(insights_input)

            # Should only process the valid lib path
            assert isinstance(result, SixteenKBPageReadyInsightResult)
            assert result.is_16kb_ready is True
            assert result.unaligned_files == []
            assert result.total_unaligned_files == 0

            # Verify LIEF parse was called exactly once (only for valid file)
            assert mock_parse.call_count == 1
