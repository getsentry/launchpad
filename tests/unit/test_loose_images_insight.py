from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.apple.loose_images import LooseImagesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import LooseImagesInsightResult
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo, TreemapType


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
                hash="hash_car",
                is_dir=False,
            ),
            # Raw images that should be flagged
            FileInfo(
                full_path=Path("icons/home.png"),
                path="icons/home.png",
                size=10240,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_home",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("icons/home@2x.png"),
                path="icons/home@2x.png",
                size=20480,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_home_2x",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("buttons/submit.jpg"),
                path="buttons/submit.jpg",
                size=15360,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash="hash_submit",
                is_dir=False,
            ),
            # Non-image file (should be ignored)
            FileInfo(
                full_path=Path("Info.plist"),
                path="Info.plist",
                size=2048,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="hash_plist",
                is_dir=False,
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 2  # Only 2 files from the multi-scale group
        assert len(result.image_groups) == 1  # Only 1 group: "home.png" (submit.jpg is single file, excluded)

        # Verify home group has both @1x and @2x variants
        home_group = next((g for g in result.image_groups if g.canonical_name == "home.png"), None)
        assert home_group is not None
        assert len(home_group.images) == 2
        assert home_group.total_size == 10240 + 20480
        # The home group's total_savings should be 10240 (excluding the larger @2x image)
        assert home_group.total_savings == 10240

        # Check total savings calculation
        # For this test case, only the home.png group qualifies (has multiple scale variants)
        # - home.png (10240) would be eliminated, home@2x.png (20480) would be kept
        # - submit.jpg is excluded because it's a single file with no scale variants
        assert result.total_savings == 10240

    def test_excludes_app_icons(self):
        """Test that AppIcon and iMessage App Icon files are excluded."""
        files = [
            FileInfo(
                full_path=Path("AppIcon-40@2x.png"),
                path="AppIcon-40@2x.png",
                size=5120,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_app_icon",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("iMessage App Icon-60@2x.png"),
                path="iMessage App Icon-60@2x.png",
                size=7168,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_imessage_icon",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("regular_icon.png"),
                path="regular_icon.png",
                size=3072,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_regular",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("regular_icon@2x.png"),
                path="regular_icon@2x.png",
                size=6144,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_regular_2x",
                is_dir=False,
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 2  # Both regular_icon files
        assert len(result.image_groups) == 1
        assert result.image_groups[0].canonical_name == "regular_icon.png"
        # Should exclude smaller image size from savings
        assert result.image_groups[0].total_savings == 3072

    def test_excludes_stickerpack_images(self):
        """Test that images in .stickerpack directories are excluded."""
        files = [
            FileInfo(
                full_path=Path("stickers.stickerpack/sticker1.png"),
                path="stickers.stickerpack/sticker1.png",
                size=5120,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_sticker",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("regular/image.png"),
                path="regular/image.png",
                size=3072,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_regular",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("regular/image@2x.png"),
                path="regular/image@2x.png",
                size=6144,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_regular_2x",
                is_dir=False,
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 2  # Both regular images
        assert len(result.image_groups) == 1
        assert result.image_groups[0].canonical_name == "image.png"
        # Should exclude smaller image size from savings
        assert result.image_groups[0].total_savings == 3072

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
                hash="hash_car",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Info.plist"),
                path="Info.plist",
                size=2048,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="hash_plist",
                is_dir=False,
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
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
                hash="hash_1x",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("icon@2x.png"),
                path="icon@2x.png",
                size=10000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_2x",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("icon@3x.png"),
                path="icon@3x.png",
                size=15000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash_3x",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("different.jpg"),
                path="different.jpg",
                size=8000,
                file_type="jpg",
                treemap_type=TreemapType.ASSETS,
                hash="hash_diff",
                is_dir=False,
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LooseImagesInsightResult)
        assert result.total_file_count == 3  # Only icon group (different.jpg is single file, excluded)
        assert len(result.image_groups) == 1

        # Find the icon group
        icon_group = next((g for g in result.image_groups if g.canonical_name == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.images) == 3  # @1x, @2x, @3x
        assert icon_group.total_size == 30000  # 5000 + 10000 + 15000
        # Should exclude the largest image (@3x = 15000) from savings
        assert icon_group.total_savings == 15000  # 5000 + 10000

        # different.jpg is excluded because it's a single file with no scale variants
