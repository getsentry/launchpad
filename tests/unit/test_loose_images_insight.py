from pathlib import Path
from unittest.mock import Mock

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.apple.loose_images import LooseImagesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import LooseImagesInsightResult
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType
from launchpad.utils.file_utils import to_nearest_block_size


class TestLooseImagesInsight:
    def setup_method(self):
        self.insight = LooseImagesInsight()

    def test_generate_with_raw_images(self):
        """Test that insight is generated when app has raw images not in asset catalogs."""
        files = [
            # Asset catalog file (.car)
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=1024000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_car",
            ),
            # Raw images that should be flagged
            FileInfo(
                full_path=Path("icons/home.png"),
                path="icons/home.png",
                size=10240,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_home",
            ),
            FileInfo(
                full_path=Path("icons/home@2x.png"),
                path="icons/home@2x.png",
                size=20480,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_home_2x",
            ),
            FileInfo(
                full_path=Path("buttons/submit.jpg"),
                path="buttons/submit.jpg",
                size=15360,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_submit",
            ),
            # Non-image file (should be ignored)
            FileInfo(
                full_path=Path("Info.plist"),
                path="Info.plist",
                size=2048,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash_md5="hash_plist",
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

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 3  # 3 raw image files
        assert len(result.image_groups) == 2  # 2 canonical groups: "home.png" and "submit.jpg"

        # Verify home group has both @1x and @2x variants
        home_group = next((g for g in result.image_groups if g.canonical_name == "home.png"), None)
        assert home_group is not None
        assert len(home_group.images) == 2
        assert home_group.total_size == 10240 + 20480

        # Verify submit group has one image
        submit_group = next((g for g in result.image_groups if g.canonical_name == "submit.jpg"), None)
        assert submit_group is not None
        assert len(submit_group.images) == 1
        assert submit_group.total_size == 15360

        # Check total savings calculation (block waste + app thinning)
        # For this test case:
        # - home.png (10240) and home@2x.png (20480): home.png would be eliminated via app thinning
        # - submit.jpg (15360): no scale indicators, so only block waste saved

        home_1x_block_size = to_nearest_block_size(10240, APPLE_FILESYSTEM_BLOCK_SIZE)  # eliminated completely
        home_2x_block_waste = to_nearest_block_size(20480, APPLE_FILESYSTEM_BLOCK_SIZE) - 20480  # remains, only waste
        submit_block_waste = to_nearest_block_size(15360, APPLE_FILESYSTEM_BLOCK_SIZE) - 15360  # no scale, only waste

        expected_savings = home_1x_block_size + home_2x_block_waste + submit_block_waste
        assert result.total_savings == expected_savings

    def test_excludes_app_icons(self):
        """Test that AppIcon and iMessage App Icon files are excluded."""
        files = [
            FileInfo(
                full_path=Path("AppIcon-40@2x.png"),
                path="AppIcon-40@2x.png",
                size=5120,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_app_icon",
            ),
            FileInfo(
                full_path=Path("iMessage App Icon-60@2x.png"),
                path="iMessage App Icon-60@2x.png",
                size=7168,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_imessage_icon",
            ),
            FileInfo(
                full_path=Path("regular_icon.png"),
                path="regular_icon.png",
                size=3072,
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

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 1  # Only regular_icon.png
        assert len(result.image_groups) == 1
        assert result.image_groups[0].canonical_name == "regular_icon.png"

    def test_excludes_deeply_nested_images(self):
        """Test that deeply nested images (>3 levels) are excluded."""
        files = [
            # Shallow - should be included
            FileInfo(
                full_path=Path("images/icon.png"),
                path="images/icon.png",
                size=5120,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_shallow",
            ),
            # Deep - should be excluded
            FileInfo(
                full_path=Path("very/deep/nested/folder/icon.png"),
                path="very/deep/nested/folder/icon.png",
                size=7168,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_deep",
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

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 1  # Only shallow image
        assert len(result.image_groups) == 1
        assert result.image_groups[0].canonical_name == "icon.png"

    def test_excludes_stickerpack_images(self):
        """Test that images in .stickerpack directories are excluded."""
        files = [
            FileInfo(
                full_path=Path("stickers.stickerpack/sticker1.png"),
                path="stickers.stickerpack/sticker1.png",
                size=5120,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_sticker",
            ),
            FileInfo(
                full_path=Path("regular/image.png"),
                path="regular/image.png",
                size=3072,
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

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 1  # Only regular image
        assert len(result.image_groups) == 1
        assert result.image_groups[0].canonical_name == "image.png"

    def test_no_raw_images_returns_none(self):
        """Test that no insight is generated when there are no raw images."""
        files = [
            # Only asset catalog and non-image files
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=1024000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_car",
            ),
            FileInfo(
                full_path=Path("Info.plist"),
                path="Info.plist",
                size=2048,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash_md5="hash_plist",
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

    def test_grouping_by_canonical_name(self):
        """Test that images are correctly grouped by canonical name."""
        files = [
            FileInfo(
                full_path=Path("icon.png"),
                path="icon.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_1x",
            ),
            FileInfo(
                full_path=Path("icon@2x.png"),
                path="icon@2x.png",
                size=10000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_2x",
            ),
            FileInfo(
                full_path=Path("icon@3x.png"),
                path="icon@3x.png",
                size=15000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_3x",
            ),
            FileInfo(
                full_path=Path("different.jpg"),
                path="different.jpg",
                size=8000,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash_md5="hash_diff",
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

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 4
        assert len(result.image_groups) == 2

        # Find the icon group
        icon_group = next((g for g in result.image_groups if g.canonical_name == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.images) == 3  # @1x, @2x, @3x
        assert icon_group.total_size == 30000  # 5000 + 10000 + 15000

        # Find the different group
        diff_group = next((g for g in result.image_groups if g.canonical_name == "different.jpg"), None)
        assert diff_group is not None
        assert len(diff_group.images) == 1
        assert diff_group.total_size == 8000
