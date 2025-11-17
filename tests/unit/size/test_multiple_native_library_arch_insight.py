from pathlib import Path

from launchpad.size.insights.android.multiple_native_library_arch import (
    MultipleNativeLibraryArchInsight,
)
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import MultipleNativeLibraryArchInsightResult
from launchpad.size.models.treemap import TreemapType


class TestMultipleNativeLibraryArchInsight:
    def setup_method(self):
        self.insight = MultipleNativeLibraryArchInsight()

    def _create_insights_input(self, files: list[FileInfo]) -> InsightsInput:
        file_analysis = FileAnalysis(items=files)
        return InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=file_analysis,
            treemap=None,
            binary_analysis=[],
        )

    def test_multiple_architectures_detected(self):
        """Test that multiple native library architectures are detected and savings calculated."""
        files = [
            # arm64-v8a libraries (keep these)
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/arm64-v8a/libcommon.so"),
                path="lib/arm64-v8a/libcommon.so",
                size=200000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_common_hash",
                is_dir=False,
            ),
            # x86_64 libraries (should be removed)
            FileInfo(
                full_path=Path("lib/x86_64/libnative.so"),
                path="lib/x86_64/libnative.so",
                size=450000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/x86_64/libcommon.so"),
                path="lib/x86_64/libcommon.so",
                size=180000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_common_hash",
                is_dir=False,
            ),
            # x86 libraries (should be removed)
            FileInfo(
                full_path=Path("lib/x86/libnative.so"),
                path="lib/x86/libnative.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
            # armeabi-v7a libraries (should be removed)
            FileInfo(
                full_path=Path("lib/armeabi-v7a/libnative.so"),
                path="lib/armeabi-v7a/libnative.so",
                size=420000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="armv7_native_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, MultipleNativeLibraryArchInsightResult)
        assert len(result.files) == 4  # All removable architecture files

        # Check that removable files are identified
        removable_paths = [f.file_path for f in result.files]
        assert "lib/x86_64/libnative.so" in removable_paths
        assert "lib/x86_64/libcommon.so" in removable_paths
        assert "lib/x86/libnative.so" in removable_paths
        assert "lib/armeabi-v7a/libnative.so" in removable_paths

        # Check that arm64-v8a files are NOT in removable files
        assert "lib/arm64-v8a/libnative.so" not in removable_paths
        assert "lib/arm64-v8a/libcommon.so" not in removable_paths

        # Check total savings
        expected_savings = 450000 + 180000 + 400000 + 420000  # 1,450,000
        assert result.total_savings == expected_savings

    def test_only_arm64_v8a_returns_none(self):
        """Test that no insight is generated when only arm64-v8a libraries are present."""
        files = [
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/arm64-v8a/libcommon.so"),
                path="lib/arm64-v8a/libcommon.so",
                size=200000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_common_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert result is None

    def test_no_native_libraries_returns_none(self):
        """Test that no insight is generated when there are no native libraries."""
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
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="dex_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert result is None

    def test_no_arm64_v8a_returns_none(self):
        """Test that no insight is generated when arm64-v8a is not present (unusual case)."""
        files = [
            FileInfo(
                full_path=Path("lib/x86_64/libnative.so"),
                path="lib/x86_64/libnative.so",
                size=450000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/armeabi-v7a/libnative.so"),
                path="lib/armeabi-v7a/libnative.so",
                size=420000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="armv7_native_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert result is None

    def test_unknown_architecture_ignored(self):
        """Test that unknown architecture directories are ignored."""
        files = [
            # arm64-v8a libraries (keep these)
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            # Unknown architecture (should be ignored)
            FileInfo(
                full_path=Path("lib/unknown-arch/libnative.so"),
                path="lib/unknown-arch/libnative.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="unknown_native_hash",
                is_dir=False,
            ),
            # x86 libraries (should be removed)
            FileInfo(
                full_path=Path("lib/x86/libnative.so"),
                path="lib/x86/libnative.so",
                size=300000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, MultipleNativeLibraryArchInsightResult)
        assert len(result.files) == 1  # Only x86 should be removable

        removable_paths = [f.file_path for f in result.files]
        assert "lib/x86/libnative.so" in removable_paths
        assert "lib/unknown-arch/libnative.so" not in removable_paths

        assert result.total_savings == 300000

    def test_non_so_files_ignored(self):
        """Test that non-.so files in lib directories are ignored."""
        files = [
            # arm64-v8a libraries
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            # x86 libraries
            FileInfo(
                full_path=Path("lib/x86/libnative.so"),
                path="lib/x86/libnative.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
            # Non-.so files in lib directories (should be ignored)
            FileInfo(
                full_path=Path("lib/x86/readme.txt"),
                path="lib/x86/readme.txt",
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.OTHER,
                hash="readme_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/arm64-v8a/config.json"),
                path="lib/arm64-v8a/config.json",
                size=500,
                file_type="json",
                treemap_type=TreemapType.OTHER,
                hash="config_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, MultipleNativeLibraryArchInsightResult)
        assert len(result.files) == 1  # Only .so files should be considered

        removable_paths = [f.file_path for f in result.files]
        assert "lib/x86/libnative.so" in removable_paths
        assert "lib/x86/readme.txt" not in removable_paths
        assert "lib/arm64-v8a/config.json" not in removable_paths

        assert result.total_savings == 400000

    def test_files_without_full_path_still_processed(self):
        """Test that files without full_path are still processed correctly."""
        files = [
            # arm64-v8a libraries
            FileInfo(
                full_path=None,
                path="lib/arm64-v8a/libnative.so",
                size=500000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            # x86 libraries
            FileInfo(
                full_path=None,
                path="lib/x86/libnative.so",
                size=400000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, MultipleNativeLibraryArchInsightResult)
        assert len(result.files) == 1

        assert result.files[0].file_path == "lib/x86/libnative.so"
        assert result.total_savings == 400000

    def test_empty_file_list_returns_none(self):
        """Test that no insight is generated with empty file list."""
        insights_input = self._create_insights_input([])
        result = self.insight.generate(insights_input)
        assert result is None

    def test_complex_scenario_with_multiple_architectures(self):
        """Test a complex scenario with multiple architectures and various file sizes."""
        files = [
            # arm64-v8a libraries (keep all these)
            FileInfo(
                full_path=Path("lib/arm64-v8a/libnative.so"),
                path="lib/arm64-v8a/libnative.so",
                size=800000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/arm64-v8a/libcommon.so"),
                path="lib/arm64-v8a/libcommon.so",
                size=300000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_common_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/arm64-v8a/libutils.so"),
                path="lib/arm64-v8a/libutils.so",
                size=150000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="arm64_utils_hash",
                is_dir=False,
            ),
            # x86_64 libraries (remove all these)
            FileInfo(
                full_path=Path("lib/x86_64/libnative.so"),
                path="lib/x86_64/libnative.so",
                size=750000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/x86_64/libcommon.so"),
                path="lib/x86_64/libcommon.so",
                size=280000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_common_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/x86_64/libutils.so"),
                path="lib/x86_64/libutils.so",
                size=140000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_64_utils_hash",
                is_dir=False,
            ),
            # x86 libraries (remove all these)
            FileInfo(
                full_path=Path("lib/x86/libnative.so"),
                path="lib/x86/libnative.so",
                size=700000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/x86/libcommon.so"),
                path="lib/x86/libcommon.so",
                size=250000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="x86_common_hash",
                is_dir=False,
            ),
            # armeabi-v7a libraries (remove all these)
            FileInfo(
                full_path=Path("lib/armeabi-v7a/libnative.so"),
                path="lib/armeabi-v7a/libnative.so",
                size=720000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="armv7_native_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("lib/armeabi-v7a/libutils.so"),
                path="lib/armeabi-v7a/libutils.so",
                size=130000,
                file_type="so",
                treemap_type=TreemapType.NATIVE_LIBRARIES,
                hash="armv7_utils_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, MultipleNativeLibraryArchInsightResult)
        assert len(result.files) == 7  # All non-arm64-v8a files

        # Check that all removable files are identified
        removable_paths = [f.file_path for f in result.files]
        expected_removable = [
            "lib/x86_64/libnative.so",
            "lib/x86_64/libcommon.so",
            "lib/x86_64/libutils.so",
            "lib/x86/libnative.so",
            "lib/x86/libcommon.so",
            "lib/armeabi-v7a/libnative.so",
            "lib/armeabi-v7a/libutils.so",
        ]

        for expected_path in expected_removable:
            assert expected_path in removable_paths

        # Check that arm64-v8a files are NOT removable
        arm64_paths = [
            "lib/arm64-v8a/libnative.so",
            "lib/arm64-v8a/libcommon.so",
            "lib/arm64-v8a/libutils.so",
        ]
        for arm64_path in arm64_paths:
            assert arm64_path not in removable_paths

        # Calculate expected total savings (sum of all non-arm64-v8a files)
        expected_savings = (
            750000
            + 280000
            + 140000  # x86_64
            + 700000
            + 250000  # x86
            + 720000
            + 130000
        )  # armeabi-v7a
        # Total: 2,970,000
        assert result.total_savings == expected_savings
