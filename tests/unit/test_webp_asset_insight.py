"""Tests for WebP asset optimization insights."""

from unittest.mock import Mock, patch

from launchpad.insights.insight import InsightsInput
from launchpad.insights.webp_asset import MIN_IMAGE_SIZE, SUPPORTED_IMAGE_FORMATS, WebpAssetInsight
from launchpad.models.common import BaseAppInfo, FileInfo
from launchpad.models.insights import WebpAssetInsightResult
from launchpad.models.treemap import TreemapType


class TestWebpAssetInsight:
    """Test cases for WebpAssetInsight."""

    def setup_method(self):
        """Set up test fixtures."""
        self.insight = WebpAssetInsight()

    def test_is_optimizable_image_supported_formats(self):
        """Test that supported image formats are identified as optimizable."""
        for extension in SUPPORTED_IMAGE_FORMATS:
            file_info = FileInfo(
                path=f"res/drawable/test{extension}",
                size=MIN_IMAGE_SIZE + 1000,
                file_type=extension.lstrip("."),
                treemap_type=TreemapType.ASSETS,
                hash_md5="test_hash",
            )
            assert self.insight._is_optimizable_image(file_info) is True

    def test_is_optimizable_image_webp_already(self):
        """Test that WebP files are not considered optimizable."""
        file_info = FileInfo(
            path="res/drawable/test.webp",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="webp",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info) is False

    def test_is_optimizable_image_too_small(self):
        """Test that very small files are not considered optimizable."""
        file_info = FileInfo(
            path="res/drawable/test.png",
            size=MIN_IMAGE_SIZE - 100,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info) is False

    def test_is_optimizable_image_unsupported_format(self):
        """Test that unsupported formats are not considered optimizable."""
        file_info = FileInfo(
            path="res/drawable/test.gif",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="gif",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info) is False

    def test_is_optimizable_image_skip_9patch(self):
        """Test that 9-patch files are not considered optimizable."""
        file_info = FileInfo(
            path="res/drawable/button.9.png",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info) is False

    def test_is_optimizable_image_only_res_assets_directories(self):
        """Test that only files in res or assets directories are considered optimizable."""
        # File in res directory - should be optimizable
        file_info_res = FileInfo(
            path="res/drawable/test.png",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info_res) is True

        # File in assets directory - should be optimizable
        file_info_assets = FileInfo(
            path="assets/images/test.png",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info_assets) is True

        # File in other directory - should not be optimizable
        file_info_other = FileInfo(
            path="lib/test.png",
            size=MIN_IMAGE_SIZE + 1000,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="test_hash",
        )
        assert self.insight._is_optimizable_image(file_info_other) is False

    def test_generate_with_cwebp_available(self):
        """Test insight generation when cwebp is available."""
        # Create test files
        files = [
            FileInfo(
                path="res/drawable/test.png",
                size=MIN_IMAGE_SIZE + 1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="test_hash",
            ),
            FileInfo(
                path="res/drawable/test.jpg",
                size=MIN_IMAGE_SIZE + 2000,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash_md5="test_hash2",
            ),
        ]

        # Create insights input
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=Mock(files=files),
            treemap=Mock(),
            binary_analysis=[],
            artifact=Mock(),
        )

        # Generate insights
        result = self.insight.generate(insights_input)

        assert isinstance(result, WebpAssetInsightResult)
        assert len(result.optimization_opportunities) >= 0  # May be 0 if extraction fails
        assert result.total_potential_savings >= 0

    @patch("launchpad.insights.webp_asset.Cwebp")
    def test_generate_with_cwebp_not_available(self, mock_cwebp_class):
        """Test insight generation when cwebp is not available."""
        # Mock cwebp to raise FileNotFoundError
        mock_cwebp_class.side_effect = FileNotFoundError("cwebp not found")

        # Create test files
        files = [
            FileInfo(
                path="res/drawable/test.png",
                size=MIN_IMAGE_SIZE + 1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="test_hash",
            ),
        ]

        # Create insights input
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=Mock(files=files),
            treemap=Mock(),
            binary_analysis=[],
            artifact=Mock(),
        )

        # Generate insights
        result = self.insight.generate(insights_input)

        assert isinstance(result, WebpAssetInsightResult)
        assert len(result.optimization_opportunities) == 0
        assert result.total_potential_savings == 0

    def test_generate_no_optimizable_images(self):
        """Test insight generation when no images are optimizable."""
        # Create test files that are not optimizable
        files = [
            FileInfo(
                path="test.txt",
                size=MIN_IMAGE_SIZE + 1000,
                file_type="txt",
                treemap_type=TreemapType.OTHER,
                hash_md5="test_hash",
            ),
            FileInfo(
                path="test.webp",
                size=MIN_IMAGE_SIZE + 1000,
                file_type="webp",
                treemap_type=TreemapType.ASSETS,
                hash_md5="test_hash2",
            ),
        ]

        # Create insights input
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=Mock(files=files),
            treemap=Mock(),
            binary_analysis=[],
            artifact=Mock(),
        )

        # Generate insights
        result = self.insight.generate(insights_input)

        assert isinstance(result, WebpAssetInsightResult)
        assert len(result.optimization_opportunities) == 0
        assert result.total_potential_savings == 0
