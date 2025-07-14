from pathlib import Path
from unittest.mock import Mock

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.apple.small_files import SmallFilesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import SmallFilesInsightResult
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType


class TestSmallFilesInsight:
    def setup_method(self):
        self.insight = SmallFilesInsight()

    def test_generate_with_many_files_and_small_files(self):
        """Test that insight is generated when app has > 100 total files with some small files."""
        # Create a mix of small and large files with total count > 100
        small_files: list[FileInfo] = []
        large_files: list[FileInfo] = []

        # Add 50 small files (< 4096 bytes)
        for i in range(50):
            small_file = FileInfo(
                full_path=Path(f"assets/small{i}.png"),
                path=f"assets/small{i}.png",
                size=1024,  # 1KB - small file
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5=f"hash_small_{i}",
            )
            small_files.append(small_file)

        # Add 60 large files (>= 4096 bytes) to bring total over 100
        for i in range(60):
            large_file = FileInfo(
                full_path=Path(f"assets/large{i}.png"),
                path=f"assets/large{i}.png",
                size=8192,  # 8KB - large file
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5=f"hash_large_{i}",
            )
            large_files.append(large_file)

        file_analysis = FileAnalysis(files=small_files + large_files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, SmallFilesInsightResult)
        assert len(result.files) == 50  # Only small files returned
        assert result.file_count == 50
        # Each small file wastes 3072 bytes (4096 - 1024)
        assert result.total_savings == 50 * (APPLE_FILESYSTEM_BLOCK_SIZE - 1024)
        # Verify all returned files are small
        for file in result.files:
            assert file.size < APPLE_FILESYSTEM_BLOCK_SIZE

    def test_generate_with_few_total_files(self):
        """Test that no insight is generated when app has <= 100 total files."""
        # Create exactly 100 files (should not trigger insight)
        files: list[FileInfo] = []
        for i in range(100):
            file = FileInfo(
                full_path=Path(f"assets/file{i}.png"),
                path=f"assets/file{i}.png",
                size=512,  # Small file
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5=f"hash_{i}",
            )
            files.append(file)

        file_analysis = FileAnalysis(files=files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # Should return None when <= 100 total files

    def test_generate_with_exactly_threshold_plus_one(self):
        """Test that insight is generated when app has exactly 101 total files."""
        # Create exactly 101 files with some small ones
        files: list[FileInfo] = []
        for i in range(101):
            size = 2048 if i < 30 else 8192  # First 30 are small, rest are large
            file = FileInfo(
                full_path=Path(f"assets/file{i}.png"),
                path=f"assets/file{i}.png",
                size=size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5=f"hash_{i}",
            )
            files.append(file)

        file_analysis = FileAnalysis(files=files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, SmallFilesInsightResult)
        assert len(result.files) == 30  # Only small files
        assert result.file_count == 30
        # Each small file wastes 2048 bytes (4096 - 2048)
        assert result.total_savings == 30 * (APPLE_FILESYSTEM_BLOCK_SIZE - 2048)

    def test_generate_with_many_files_but_no_small_files(self):
        """Test that insight is generated but with empty results when no small files exist."""
        # Create 150 files, all large (>= 4096 bytes)
        files: list[FileInfo] = []
        for i in range(150):
            file = FileInfo(
                full_path=Path(f"assets/file{i}.png"),
                path=f"assets/file{i}.png",
                size=8192,  # All large files
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5=f"hash_{i}",
            )
            files.append(file)

        file_analysis = FileAnalysis(files=files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, SmallFilesInsightResult)
        assert len(result.files) == 0  # No small files
        assert result.file_count == 0
        assert result.total_savings == 0

    def test_generate_with_empty_file_list(self):
        """Test that no insight is generated when there are no files."""
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # No files means no insight

    def test_generate_with_edge_case_file_sizes(self):
        """Test with files at filesystem block size boundary."""
        files: list[FileInfo] = []

        # Add files to get over 100 total
        for i in range(105):
            if i < 20:
                # Files exactly at block size - should not be considered small
                size = APPLE_FILESYSTEM_BLOCK_SIZE
            elif i < 40:
                # Files just under block size - should be considered small
                size = APPLE_FILESYSTEM_BLOCK_SIZE - 1
            else:
                # Regular large files
                size = 8192

            file = FileInfo(
                full_path=Path(f"assets/file{i}.bin"),
                path=f"assets/file{i}.bin",
                size=size,
                file_type="bin",
                treemap_type=TreemapType.OTHER,
                hash_md5=f"hash_{i}",
            )
            files.append(file)

        file_analysis = FileAnalysis(files=files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, SmallFilesInsightResult)
        assert len(result.files) == 20  # Only files under block size
        assert result.file_count == 20
        # Each small file wastes 1 byte (4096 - 4095)
        assert result.total_savings == 20 * 1

    def test_calculate_savings_correctly(self):
        """Test that savings calculation is correct for various file sizes."""
        files: list[FileInfo] = []
        expected_savings = 0

        # Add files to get over 100 total, with specific sizes for testing savings calculation
        test_sizes = [1, 512, 1024, 2048, 3000, 4095]  # All under 4096

        for i, size in enumerate(test_sizes):
            file = FileInfo(
                full_path=Path(f"assets/test{i}.bin"),
                path=f"assets/test{i}.bin",
                size=size,
                file_type="bin",
                treemap_type=TreemapType.OTHER,
                hash_md5=f"hash_{i}",
            )
            files.append(file)
            expected_savings += APPLE_FILESYSTEM_BLOCK_SIZE - size

        # Add enough large files to exceed 100 total
        for i in range(100):
            file = FileInfo(
                full_path=Path(f"assets/large{i}.bin"),
                path=f"assets/large{i}.bin",
                size=8192,
                file_type="bin",
                treemap_type=TreemapType.OTHER,
                hash_md5=f"hash_large_{i}",
            )
            files.append(file)

        file_analysis = FileAnalysis(files=files)

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, SmallFilesInsightResult)
        assert len(result.files) == len(test_sizes)
        assert result.file_count == len(test_sizes)
        assert result.total_savings == expected_savings
