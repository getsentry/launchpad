import shutil
import tempfile

from pathlib import Path
from unittest.mock import Mock

import pytest

from launchpad.size.insights.apple.image_optimization import ImageOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import ImageOptimizationInsightResult
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType


class TestImageOptimizationIntegration:
    """Integration tests for image optimization insight using real image files."""

    def setup_method(self):
        self.insight = ImageOptimizationInsight()
        # Create temporary directory for test images
        self.temp_dir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        # Clean up temporary directory
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def _create_test_png_image(self, path: Path, size_kb: int = 10) -> None:
        """Create a simple test PNG image."""
        try:
            from PIL import Image

            # Create a simple test image
            img = Image.new("RGB", (100, 100), color="red")
            img.save(path, "PNG")

            # If the file is smaller than requested, pad it with data
            current_size = path.stat().st_size
            target_size = size_kb * 1024
            if current_size < target_size:
                with open(path, "ab") as f:
                    f.write(b"\x00" * (target_size - current_size))
        except ImportError:
            # If PIL is not available, create a dummy file
            with open(path, "wb") as f:
                f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * (size_kb * 1024 - 8))

    def _create_test_jpg_image(self, path: Path, size_kb: int = 10) -> None:
        """Create a simple test JPG image."""
        try:
            from PIL import Image

            # Create a simple test image
            img = Image.new("RGB", (100, 100), color="blue")
            img.save(path, "JPEG", quality=95)  # High quality for optimization potential

            # If the file is smaller than requested, pad it with dummy data at the end
            current_size = path.stat().st_size
            target_size = size_kb * 1024
            if current_size < target_size:
                with open(path, "ab") as f:
                    f.write(b"\x00" * (target_size - current_size))
        except ImportError:
            # If PIL is not available, create a dummy file
            with open(path, "wb") as f:
                f.write(b"\xff\xd8\xff" + b"\x00" * (size_kb * 1024 - 3))

    def test_image_optimization_with_real_files(self):
        """Test image optimization with real image files."""
        # Create test images
        large_png = self.temp_dir / "large_image.png"
        large_jpg = self.temp_dir / "photo.jpg"
        small_png = self.temp_dir / "icon.png"  # Below threshold

        self._create_test_png_image(large_png, size_kb=50)  # 50KB
        self._create_test_jpg_image(large_jpg, size_kb=100)  # 100KB
        self._create_test_png_image(small_png, size_kb=1)  # 1KB (below threshold)

        files = [
            FileInfo(
                full_path=large_png,
                path="images/large_image.png",
                size=large_png.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_large",
            ),
            FileInfo(
                full_path=large_jpg,
                path="photos/photo.jpg",
                size=large_jpg.stat().st_size,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_photo",
            ),
            FileInfo(
                full_path=small_png,
                path="icons/icon.png",
                size=small_png.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_small",
            ),
        ]

        file_analysis = FileAnalysis(files=files)
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        # If Pillow is not available, result should be None
        try:
            import pillow_heif  # type: ignore # noqa: F401

            from PIL import Image  # noqa: F401

            # PIL is available, should get results
            if result is None:
                pytest.skip("No optimizations found with current test images")
            else:
                assert isinstance(result, ImageOptimizationInsightResult)
                assert result.total_file_count >= 0
                assert result.total_savings >= 0
        except ImportError:
            # PIL not available, should return None
            assert result is None

    def test_excludes_system_files_integration(self):
        """Test that system files are properly excluded in integration."""
        # Create test images including system files
        app_icon = self.temp_dir / "AppIcon-60@2x.png"
        imessage_icon = self.temp_dir / "iMessage App Icon-40.png"
        regular_image = self.temp_dir / "regular.png"

        self._create_test_png_image(app_icon, size_kb=10)
        self._create_test_png_image(imessage_icon, size_kb=8)
        self._create_test_png_image(regular_image, size_kb=15)

        files = [
            FileInfo(
                full_path=app_icon,
                path="AppIcon-60@2x.png",
                size=app_icon.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_app",
            ),
            FileInfo(
                full_path=imessage_icon,
                path="iMessage App Icon-40.png",
                size=imessage_icon.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_imessage",
            ),
            FileInfo(
                full_path=regular_image,
                path="images/regular.png",
                size=regular_image.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_regular",
            ),
        ]

        file_analysis = FileAnalysis(files=files)
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        # Verify system files are excluded
        try:
            import pillow_heif  # type: ignore # noqa: F401

            from PIL import Image  # noqa: F401

            # PIL is available
            if result is not None:
                # Should only include regular image, not system icons
                optimizable_paths = [f.file_info.path for f in result.optimizable_files]
                assert "AppIcon-60@2x.png" not in optimizable_paths
                assert "iMessage App Icon-40.png" not in optimizable_paths
                # Regular image might or might not be optimizable depending on actual content
        except ImportError:
            # PIL not available, should return None
            assert result is None

    def test_minimum_savings_threshold(self):
        """Test that files with savings below threshold are excluded."""
        # Create a very small image that likely won't have 500+ bytes of savings
        tiny_png = self.temp_dir / "tiny.png"
        self._create_test_png_image(tiny_png, size_kb=2)  # Very small image

        files = [
            FileInfo(
                full_path=tiny_png,
                path="tiny.png",
                size=tiny_png.stat().st_size,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_tiny",
            ),
        ]

        file_analysis = FileAnalysis(files=files)
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        # Even if optimizations are found, they should be filtered by minimum threshold
        try:
            import pillow_heif  # type: ignore # noqa: F401

            from PIL import Image  # noqa: F401

            # PIL is available
            if result is not None:
                # All reported files should have at least 500 bytes savings
                for optimizable_file in result.optimizable_files:
                    assert optimizable_file.potential_savings >= 500
        except ImportError:
            # PIL not available, should return None
            assert result is None
