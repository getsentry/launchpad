"""Tests for image optimization insight in AndroidAnalyzer."""

import tempfile

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from launchpad.analyzers.android import AndroidAnalyzer
from launchpad.models.insights import ImageOptimizationInsightResult


class TestImageOptimizationInsight:
    def setup_method(self):
        self.analyzer = AndroidAnalyzer()

    @patch("launchpad.utils.android.cwebp.Cwebp.convert_to_webp")
    def test_get_image_optimization_insight_with_optimizable_images(self, mock_cwebp_class):
        """Test image optimization when there are optimizable images."""
        mock_cwebp = Mock()
        mock_cwebp_class.return_value = mock_cwebp

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            res_dir = temp_path / "res" / "drawable"
            res_dir.mkdir(parents=True)
            assets_dir = temp_path / "assets" / "images"
            assets_dir.mkdir(parents=True)

            test_image1 = res_dir / "test_image.png"
            test_image1.write_bytes(b"fake png data" * 1000)  # Make it large enough

            test_image2 = assets_dir / "banner.jpg"
            test_image2.write_bytes(b"fake jpg data" * 1000)

            mock_apk = Mock()
            mock_apk.get_extract_path.return_value = temp_path

            def convert_side_effect(input_path, output_path):
                output_path.write_bytes(b"webp" * 100)  # Much smaller
                return True

            mock_cwebp.convert_to_webp.side_effect = convert_side_effect

            result = self.analyzer._get_image_optimization_insight([mock_apk])

            assert isinstance(result, ImageOptimizationInsightResult)
            assert len(result.images) == 2
            assert result.total_savings > 0

            image_paths = [img.path for img in result.images]
            assert "res/drawable/test_image.png" in image_paths
            assert "assets/images/banner.jpg" in image_paths

    @patch("launchpad.utils.android.cwebp.Cwebp._find_cwebp", return_value=None)
    def test_get_image_optimization_insight_cwebp_not_found(self, mock_cwebp_class):
        """Test image optimization when cwebp is not available."""
        mock_apk = Mock()

        # The code should now raise FileNotFoundError when cwebp is not found
        with pytest.raises(FileNotFoundError, match="cwebp binary not found in PATH"):
            self.analyzer._get_image_optimization_insight([mock_apk])

    @patch("launchpad.utils.android.cwebp.Cwebp._find_cwebp", return_value=None)
    def test_get_image_optimization_insight_no_savings(self, mock_cwebp_class):
        """Test image optimization when WebP doesn't provide savings."""
        mock_cwebp = Mock()
        mock_cwebp_class.return_value = mock_cwebp

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            res_dir = temp_path / "res" / "drawable"
            res_dir.mkdir(parents=True)

            test_image = res_dir / "test_image.png"
            test_image.write_bytes(b"fake png data" * 100)

            mock_apk = Mock()
            mock_apk.get_extract_path.return_value = temp_path

            def convert_side_effect(input_path, output_path):
                original_size = input_path.stat().st_size
                output_path.write_bytes(b"w" * (original_size - 100))  # Only 100 bytes savings
                return True

            mock_cwebp.convert_to_webp.side_effect = convert_side_effect

            result = self.analyzer._get_image_optimization_insight([mock_apk])

            assert isinstance(result, ImageOptimizationInsightResult)
            assert len(result.images) == 0  # No images meet the 500 byte threshold
            assert result.total_savings == 0

    @patch("launchpad.utils.android.cwebp.Cwebp.convert_to_webp")
    def test_get_image_optimization_insight_skip_webp_and_9patch(self, mock_cwebp_class):
        """Test that WebP and 9-patch images are skipped."""
        mock_cwebp = Mock()
        mock_cwebp_class.return_value = mock_cwebp

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            res_dir = temp_path / "res" / "drawable"
            res_dir.mkdir(parents=True)

            webp_file = res_dir / "already_optimized.webp"
            webp_file.write_bytes(b"webp data" * 1000)

            nine_patch = res_dir / "button.9.png"
            nine_patch.write_bytes(b"9patch data" * 1000)

            normal_image = res_dir / "icon.png"
            normal_image.write_bytes(b"png data" * 1000)

            mock_apk = Mock()
            mock_apk.get_extract_path.return_value = temp_path

            def convert_side_effect(input_path, output_path):
                output_path.write_bytes(b"webp" * 100)
                return True

            mock_cwebp.convert_to_webp.side_effect = convert_side_effect

            result = self.analyzer._get_image_optimization_insight([mock_apk])

            assert isinstance(result, ImageOptimizationInsightResult)
            assert len(result.images) == 1  # Only the normal PNG
            assert result.images[0].path == "res/drawable/icon.png"
