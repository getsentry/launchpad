"""Integration tests for ImageOptimizationInsight using real image files."""

from __future__ import annotations

import tempfile

from pathlib import Path
from typing import Any, Dict

import pytest

from PIL import Image

from launchpad.size.insights.apple.image_optimization import ImageOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType
from launchpad.utils.file_utils import calculate_file_hash


class TestImageOptimizationInsightIntegration:
    """Integration tests for ImageOptimizationInsight with real image files."""

    @pytest.fixture
    def insight(self) -> ImageOptimizationInsight:
        """Create an ImageOptimizationInsight instance."""
        return ImageOptimizationInsight()

    @pytest.fixture
    def temp_images(self):
        """Create temporary test images in various formats."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a large unoptimized PNG (should have minification savings)
            large_png = temp_path / "large_unoptimized.png"
            img = Image.new("RGBA", (1000, 1000), (255, 0, 0, 128))
            img.save(large_png, format="PNG", optimize=False, compress_level=0)

            # Create a small optimized PNG (should not trigger threshold)
            small_png = temp_path / "small_optimized.png"
            small_img = Image.new("RGB", (50, 50), (0, 255, 0))
            small_img.save(small_png, format="PNG", optimize=True)

            # Create a JPEG that could benefit from HEIC conversion
            large_jpeg = temp_path / "large_photo.jpg"
            jpeg_img = Image.new("RGB", (2000, 1500), (100, 150, 200))
            jpeg_img.save(large_jpeg, format="JPEG", quality=95)

            # Create an App Icon (should be excluded)
            app_icon = temp_path / "AppIcon60x60@2x.png"
            icon_img = Image.new("RGB", (120, 120), (255, 255, 255))
            icon_img.save(app_icon, format="PNG")

            # Create an image in a sticker pack (should be excluded)
            sticker_dir = temp_path / "Stickers.stickerpack"
            sticker_dir.mkdir()
            sticker_image = sticker_dir / "sticker.png"
            sticker_img = Image.new("RGB", (100, 100), (255, 0, 255))
            sticker_img.save(sticker_image, format="PNG")

            yield {
                "large_png": large_png,
                "small_png": small_png,
                "large_jpeg": large_jpeg,
                "app_icon": app_icon,
                "sticker_image": sticker_image,
                "temp_dir": temp_path,
            }

    @pytest.fixture
    def sample_file_analysis(self, temp_images: Dict[str, Any]) -> FileAnalysis:
        """Create a FileAnalysis with the test images."""
        files: list[FileInfo] = []

        for name, path in temp_images.items():
            if name == "temp_dir":
                continue

            if isinstance(path, Path) and path.exists():
                file_info = FileInfo(
                    path=str(path.relative_to(temp_images["temp_dir"])),
                    full_path=path,
                    size=path.stat().st_size,
                    file_type=path.suffix[1:].lower() if path.suffix else "unknown",
                    hash_md5=calculate_file_hash(path),
                    treemap_type=TreemapType.ASSETS,
                    children=[],
                )
                files.append(file_info)

        return FileAnalysis(files=files)

    @pytest.fixture
    def insights_input(self, sample_file_analysis: FileAnalysis) -> InsightsInput:
        """Create InsightsInput for testing."""
        app_info = AppleAppInfo(
            name="TestApp",
            app_id="com.test.app",
            version="1.0",
            build="1",
            executable="TestApp",
            minimum_os_version="15.0",
            supported_platforms=["iphoneos"],
            sdk_version=None,
            is_simulator=False,
            codesigning_type=None,
            profile_name=None,
            is_code_signature_valid=True,
            code_signature_errors=[],
        )

        return InsightsInput(
            app_info=app_info,
            file_analysis=sample_file_analysis,
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

    def test_generates_optimization_results_for_large_images(
        self, insight: ImageOptimizationInsight, insights_input: InsightsInput
    ) -> None:
        """Test that the insight generates optimization results for large, unoptimized images."""
        result = insight.generate(insights_input)

        assert result is not None
        assert result.total_savings > 0
        assert len(result.optimizable_files) > 0

        optimizable_paths = {f.file_info.path for f in result.optimizable_files}
        assert any("large_unoptimized.png" in path for path in optimizable_paths)
        assert any("large_photo.jpg" in path for path in optimizable_paths)

    def test_excludes_app_icons_and_sticker_packs(
        self, insight: ImageOptimizationInsight, insights_input: InsightsInput
    ) -> None:
        """Test that App Icons and sticker pack images are excluded from optimization."""
        result = insight.generate(insights_input)
        assert result is not None
        optimizable_paths = {f.file_info.path for f in result.optimizable_files}
        assert not any("AppIcon" in path for path in optimizable_paths)
        assert not any("stickerpack" in path for path in optimizable_paths)

    def test_respects_minimum_savings_threshold(
        self, insight: ImageOptimizationInsight, insights_input: InsightsInput
    ) -> None:
        """Test that only images with savings above the threshold are included."""
        result = insight.generate(insights_input)
        assert result is not None
        for optimizable_file in result.optimizable_files:
            assert optimizable_file.potential_savings >= insight.MIN_SAVINGS_THRESHOLD

    def test_calculates_minification_savings(
        self, insight: ImageOptimizationInsight, temp_images: Dict[str, Any], insights_input: InsightsInput
    ) -> None:
        """Test that minification savings are calculated correctly."""
        large_png = temp_images["large_png"]
        file_info = FileInfo(
            path="large_unoptimized.png",
            full_path=large_png,
            size=large_png.stat().st_size,
            file_type="png",
            hash_md5=calculate_file_hash(large_png),
            treemap_type=TreemapType.ASSETS,
            children=[],
        )

        png_only_input = InsightsInput(
            app_info=insights_input.app_info,
            file_analysis=FileAnalysis(files=[file_info]),
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        result = insight.generate(png_only_input)

        assert result is not None
        assert result.total_savings > 0
        assert len(result.optimizable_files) == 1

        optimizable_file = result.optimizable_files[0]
        assert optimizable_file.minify_savings > 0
        assert optimizable_file.minified_size is not None
        assert optimizable_file.minified_size < optimizable_file.current_size

    def test_calculates_heic_conversion_savings(
        self, insight: ImageOptimizationInsight, temp_images: Dict[str, Any], insights_input: InsightsInput
    ) -> None:
        """Test that HEIC conversion savings are calculated for JPEG images."""
        large_jpeg = temp_images["large_jpeg"]
        file_info = FileInfo(
            path="large_photo.jpg",
            full_path=large_jpeg,
            size=large_jpeg.stat().st_size,
            file_type="jpg",
            hash_md5=calculate_file_hash(large_jpeg),
            treemap_type=TreemapType.ASSETS,
            children=[],
        )

        jpeg_only_input = InsightsInput(
            app_info=insights_input.app_info,
            file_analysis=FileAnalysis(files=[file_info]),
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        result = insight.generate(jpeg_only_input)

        assert result is not None, "Expected optimization results for large JPEG file"
        assert result.total_savings > 0, "Expected total savings > 0 for large JPEG"
        assert len(result.optimizable_files) >= 1, "Expected at least one optimizable file"

        jpeg_result = next((f for f in result.optimizable_files if "large_photo.jpg" in f.file_info.path), None)
        assert jpeg_result is not None, "Expected to find large_photo.jpg in optimization results"

        # For a large JPEG (2000x1500 at quality=95), HEIC should provide savings
        assert jpeg_result.conversion_savings > 0, "Expected HEIC conversion to provide savings for large JPEG"
        assert jpeg_result.heic_size is not None, "Expected heic_size to be set for HEIC conversion"
        assert jpeg_result.heic_size < jpeg_result.current_size, (
            "Expected HEIC size to be smaller than current JPEG size"
        )

    def test_handles_corrupted_images_gracefully(
        self, insight: ImageOptimizationInsight, temp_images: Dict[str, Any], insights_input: InsightsInput
    ) -> None:
        """Test that corrupted or invalid image files are handled gracefully."""
        corrupted_file = temp_images["temp_dir"] / "corrupted.png"
        corrupted_file.write_text("This is not an image file")

        file_info = FileInfo(
            path="corrupted.png",
            full_path=corrupted_file,
            size=corrupted_file.stat().st_size,
            file_type="png",
            hash_md5=calculate_file_hash(corrupted_file),
            treemap_type=TreemapType.ASSETS,
            children=[],
        )

        corrupted_input = InsightsInput(
            app_info=insights_input.app_info,
            file_analysis=FileAnalysis(files=[file_info]),
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        # Should not raise an exception and should return None (no optimizable files)
        result = insight.generate(corrupted_input)
        assert result is None, "Expected None when all files are corrupted/invalid"

    def test_empty_file_list_returns_none(self, insight: ImageOptimizationInsight) -> None:
        """Test that an empty file list returns None."""
        empty_input = InsightsInput(
            app_info=AppleAppInfo(
                name="TestApp",
                app_id="com.test.app",
                version="1.0",
                build="1",
                executable="TestApp",
                minimum_os_version="15.0",
                supported_platforms=["iphoneos"],
                sdk_version=None,
                is_simulator=False,
                codesigning_type=None,
                profile_name=None,
                is_code_signature_valid=True,
                code_signature_errors=[],
            ),
            file_analysis=FileAnalysis(files=[]),
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        result = insight.generate(empty_input)
        assert result is None

    def test_only_small_savings_returns_none(
        self, insight: ImageOptimizationInsight, temp_images: Dict[str, Any], insights_input: InsightsInput
    ) -> None:
        """Test that if all images have savings below threshold, None is returned."""
        small_png = temp_images["small_png"]

        file_analysis = FileAnalysis(
            files=[
                FileInfo(
                    path="small_optimized.png",
                    full_path=small_png,
                    size=small_png.stat().st_size,
                    file_type="png",
                    hash_md5=calculate_file_hash(small_png),
                    treemap_type=TreemapType.ASSETS,
                    children=[],
                )
            ]
        )

        small_input = InsightsInput(
            app_info=insights_input.app_info,
            file_analysis=file_analysis,
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        result = insight.generate(small_input)
        assert result is None
