from pathlib import Path
from unittest.mock import Mock, mock_open, patch

from launchpad.size.insights.apple.image_optimization import ImageOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import ImageOptimizationInsightResult, OptimizableImageFile
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType


class TestImageOptimizationInsight:
    def setup_method(self):
        self.insight = ImageOptimizationInsight()

    @patch("launchpad.size.insights.apple.image_optimization.pillow_available", True)
    @patch("launchpad.size.insights.apple.image_optimization.Image")
    def test_generate_with_optimizable_images(self, mock_image_class):
        """Test that insight is generated when app has optimizable images."""
        # Mock PIL Image
        mock_img = Mock()
        mock_img.format = "PNG"
        mock_img.mode = "RGB"
        mock_img.save = Mock()
        mock_image_class.open.return_value.__enter__.return_value = mock_img

        files = [
            FileInfo(
                full_path=Path("images/large.png"),
                path="images/large.png",
                size=50000,  # 50KB
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_large",
            ),
            FileInfo(
                full_path=Path("photos/picture.jpg"),
                path="photos/picture.jpg",
                size=100000,  # 100KB
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_picture",
            ),
            # Small image that should be skipped
            FileInfo(
                full_path=Path("icons/tiny.png"),
                path="icons/tiny.png",
                size=500,  # Too small
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

        # Mock file reading and optimization results
        def mock_open_side_effect(path, mode="rb"):
            if "large.png" in str(path):
                return mock_open(read_data=b"PNG_DATA" * 1000)()
            elif "picture.jpg" in str(path):
                return mock_open(read_data=b"JPEG_DATA" * 2000)()
            return mock_open(read_data=b"")()

        with patch("builtins.open", side_effect=mock_open_side_effect):
            with patch.object(self.insight, "_analyze_image_optimization") as mock_analyze:
                # Mock optimization results with savings above threshold
                mock_analyze.side_effect = [
                    [
                        OptimizableImageFile(
                            file_info=files[0],
                            optimization_type="minify",
                            current_size=50000,
                            optimized_size=45000,
                        )
                    ],
                    [
                        OptimizableImageFile(
                            file_info=files[1],
                            optimization_type="convert_to_heic",
                            current_size=100000,
                            optimized_size=85000,
                        )
                    ],
                ]

                result = self.insight.generate(insights_input)

        assert isinstance(result, ImageOptimizationInsightResult)
        assert result.total_file_count == 2
        assert len(result.optimizable_files) == 2
        assert result.total_savings == 20000  # 5000 + 15000

    @patch("launchpad.size.insights.apple.image_optimization.pillow_available", False)
    def test_pillow_not_available_returns_none(self):
        """Test that no insight is generated when Pillow is not available."""
        files = [
            FileInfo(
                full_path=Path("image.png"),
                path="image.png",
                size=10000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash",
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
        assert result is None

    def test_excludes_system_files(self):
        """Test that system icons and special files are excluded."""
        files = [
            FileInfo(
                full_path=Path("AppIcon-60@2x.png"),
                path="AppIcon-60@2x.png",
                size=10000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_app",
            ),
            FileInfo(
                full_path=Path("iMessage App Icon-40.png"),
                path="iMessage App Icon-40.png",
                size=8000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_imessage",
            ),
            FileInfo(
                full_path=Path("stickers.stickerpack/sticker.png"),
                path="stickers.stickerpack/sticker.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_sticker",
            ),
            FileInfo(
                full_path=Path("regular.png"),
                path="regular.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_regular",
            ),
        ]

        # Test _is_optimizable_image method directly
        assert not self.insight._is_optimizable_image(files[0])  # AppIcon
        assert not self.insight._is_optimizable_image(files[1])  # iMessage App Icon
        assert not self.insight._is_optimizable_image(files[2])  # .stickerpack
        assert self.insight._is_optimizable_image(files[3])  # regular image

    def test_excludes_small_images(self):
        """Test that very small images are excluded from optimization."""
        small_file = FileInfo(
            full_path=Path("tiny.png"),
            path="tiny.png",
            size=500,  # Less than 1KB threshold
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash_tiny",
        )

        assert not self.insight._is_optimizable_image(small_file)

    def test_excludes_non_image_files(self):
        """Test that non-image files are excluded."""
        text_file = FileInfo(
            full_path=Path("data.txt"),
            path="data.txt",
            size=5000,
            file_type="txt",
            treemap_type=TreemapType.OTHER,
            hash_md5="hash_txt",
        )

        assert not self.insight._is_optimizable_image(text_file)

    @patch("launchpad.size.insights.apple.image_optimization.pillow_available", True)
    def test_no_optimizable_images_returns_none(self):
        """Test that no insight is generated when there are no optimizable images."""
        files = [
            FileInfo(
                full_path=Path("AppIcon-60.png"),
                path="AppIcon-60.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_app",
            ),
            FileInfo(
                full_path=Path("tiny.png"),
                path="tiny.png",
                size=500,
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
        assert result is None

    def test_optimizable_image_file_potential_savings(self):
        """Test the potential_savings property of OptimizableImageFile."""
        file_info = FileInfo(
            full_path=Path("test.png"),
            path="test.png",
            size=10000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash",
        )

        optimizable_file = OptimizableImageFile(
            file_info=file_info,
            optimization_type="minify",
            current_size=10000,
            optimized_size=8000,
        )

        assert optimizable_file.potential_savings == 2000

    def test_optimizable_image_file_no_negative_savings(self):
        """Test that potential_savings never goes negative."""
        file_info = FileInfo(
            full_path=Path("test.png"),
            path="test.png",
            size=10000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash",
        )

        # Case where optimized size is larger (shouldn't happen, but test for robustness)
        optimizable_file = OptimizableImageFile(
            file_info=file_info,
            optimization_type="minify",
            current_size=8000,
            optimized_size=10000,
        )

        assert optimizable_file.potential_savings == 0
