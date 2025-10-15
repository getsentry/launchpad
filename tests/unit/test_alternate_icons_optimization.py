import tempfile

from pathlib import Path
from unittest.mock import Mock

from PIL import Image

from launchpad.size.insights.apple.alternate_icons_optimization import AlternateIconsOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import FileAnalysis, FileInfo, TreemapType
from launchpad.size.models.insights import ImageOptimizationInsightResult


class TestAlternateIconsOptimizationInsight:
    def setup_method(self):
        self.insight = AlternateIconsOptimizationInsight()

    def _create_test_png(self, size: tuple[int, int], quality: int = 100, optimized: bool = False) -> Path:
        """Create a test PNG image and return its path."""
        temp_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        temp_path = Path(temp_file.name)
        temp_file.close()

        # Create an image with some variety to ensure it has optimization potential
        img = Image.new("RGB", size, color=(255, 0, 0))
        # Add some gradient to make the image less uniform
        pixels = img.load()
        for i in range(size[0]):
            for j in range(size[1]):
                pixels[i, j] = (255 - i % 256, j % 256, (i + j) % 256)

        img.save(temp_path, format="PNG", optimize=optimized, compress_level=0 if not optimized else 9)

        return temp_path

    def test_no_alternate_icons_returns_none(self):
        """Test that insight is not generated when no alternate icons are defined."""
        app_info = AppleAppInfo(
            name="TestApp",
            version="1.0",
            build="1",
            app_id="com.test.app",
            executable="TestApp",
            minimum_os_version="14.0",
            primary_icon_name="AppIcon",
            alternate_icon_names=[],  # No alternate icons
        )

        files = [
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=1024000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="hash_car",
                is_dir=False,
                children=[],
            ),
        ]

        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=app_info,
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_non_apple_app_info_returns_none(self):
        """Test that insight is not generated for non-Apple apps."""
        from launchpad.size.models.common import BaseAppInfo

        app_info = BaseAppInfo(
            name="TestApp",
            version="1.0",
            build="1",
            app_id="com.test.app",
        )

        files = []
        file_analysis = FileAnalysis(files=files, directories=[])
        insights_input = InsightsInput(
            app_info=app_info,
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_identifies_alternate_icons(self):
        """Test that alternate icons are correctly identified and analyzed."""
        # Create test images (larger and unoptimized to ensure savings > 4KB)
        primary_icon_path = self._create_test_png((200, 200), optimized=False)
        alt_icon1_path = self._create_test_png((200, 200), optimized=False)
        alt_icon2_path = self._create_test_png((200, 200), optimized=False)

        try:
            app_info = AppleAppInfo(
                name="TestApp",
                version="1.0",
                build="1",
                app_id="com.test.app",
                executable="TestApp",
                minimum_os_version="14.0",
                primary_icon_name="AppIcon",
                alternate_icon_names=["DarkIcon", "LightIcon"],
            )

            # Simulate asset catalog with primary and alternate icons
            files = [
                FileInfo(
                    full_path=Path("Assets.car"),
                    path="Assets.car",
                    size=500000,
                    file_type="car",
                    treemap_type=TreemapType.ASSETS,
                    hash="hash_car",
                    is_dir=False,
                    children=[
                        # Primary icon - should be excluded
                        FileInfo(
                            full_path=primary_icon_path,
                            path="Assets.car/AppIcon-60@2x",
                            size=primary_icon_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_primary",
                            is_dir=False,
                        ),
                        # Alternate icons - should be included
                        FileInfo(
                            full_path=alt_icon1_path,
                            path="Assets.car/DarkIcon-60@2x",
                            size=alt_icon1_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_dark",
                            is_dir=False,
                        ),
                        FileInfo(
                            full_path=alt_icon2_path,
                            path="Assets.car/LightIcon-60@2x",
                            size=alt_icon2_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_light",
                            is_dir=False,
                        ),
                    ],
                ),
            ]

            file_analysis = FileAnalysis(files=files, directories=[])
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                treemap=Mock(),
                binary_analysis=[],
            )

            result = self.insight.generate(insights_input)

            assert isinstance(result, ImageOptimizationInsightResult)
            # Should only include alternate icons, not primary
            assert len(result.optimizable_files) == 2
            assert result.total_savings > 0

            # Verify correct icons are included
            paths = [f.file_path for f in result.optimizable_files]
            assert any("DarkIcon" in p for p in paths)
            assert any("LightIcon" in p for p in paths)
            assert not any("AppIcon" in p for p in paths)

        finally:
            # Clean up test files
            primary_icon_path.unlink(missing_ok=True)
            alt_icon1_path.unlink(missing_ok=True)
            alt_icon2_path.unlink(missing_ok=True)

    def test_excludes_primary_icon(self):
        """Test that primary icon is excluded even if it has potential savings."""
        primary_icon_path = self._create_test_png((200, 200), optimized=False)
        alt_icon_path = self._create_test_png((200, 200), optimized=False)

        try:
            app_info = AppleAppInfo(
                name="TestApp",
                version="1.0",
                build="1",
                app_id="com.test.app",
                executable="TestApp",
                minimum_os_version="14.0",
                primary_icon_name="PrimaryIcon",
                alternate_icon_names=["AlternateIcon"],
            )

            files = [
                FileInfo(
                    full_path=Path("Assets.car"),
                    path="Assets.car",
                    size=500000,
                    file_type="car",
                    treemap_type=TreemapType.ASSETS,
                    hash="hash_car",
                    is_dir=False,
                    children=[
                        FileInfo(
                            full_path=primary_icon_path,
                            path="Assets.car/PrimaryIcon-60@2x",
                            size=primary_icon_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_primary",
                            is_dir=False,
                        ),
                        FileInfo(
                            full_path=alt_icon_path,
                            path="Assets.car/AlternateIcon-60@2x",
                            size=alt_icon_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_alt",
                            is_dir=False,
                        ),
                    ],
                ),
            ]

            file_analysis = FileAnalysis(files=files, directories=[])
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                treemap=Mock(),
                binary_analysis=[],
            )

            result = self.insight.generate(insights_input)

            if result:  # May be None if savings are too small
                # Ensure primary icon is not included
                paths = [f.file_path for f in result.optimizable_files]
                assert not any("PrimaryIcon" in p for p in paths)

        finally:
            primary_icon_path.unlink(missing_ok=True)
            alt_icon_path.unlink(missing_ok=True)

    def test_no_optimizable_icons_returns_none(self):
        """Test that insight is not generated when alternate icons have no optimization opportunities."""
        app_info = AppleAppInfo(
            name="TestApp",
            version="1.0",
            build="1",
            app_id="com.test.app",
            executable="TestApp",
            minimum_os_version="14.0",
            primary_icon_name="AppIcon",
            alternate_icon_names=["AlternateIcon"],
        )

        # No asset catalogs or icons
        files = [
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
            app_info=app_info,
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_minimum_savings_threshold(self):
        """Test that files below minimum savings threshold are excluded."""
        # Create a very small image that won't meet the 4KB savings threshold
        small_icon_path = self._create_test_png((16, 16), quality=95)

        try:
            app_info = AppleAppInfo(
                name="TestApp",
                version="1.0",
                build="1",
                app_id="com.test.app",
                executable="TestApp",
                minimum_os_version="14.0",
                primary_icon_name="AppIcon",
                alternate_icon_names=["TinyIcon"],
            )

            files = [
                FileInfo(
                    full_path=Path("Assets.car"),
                    path="Assets.car",
                    size=10000,
                    file_type="car",
                    treemap_type=TreemapType.ASSETS,
                    hash="hash_car",
                    is_dir=False,
                    children=[
                        FileInfo(
                            full_path=small_icon_path,
                            path="Assets.car/TinyIcon-16",
                            size=small_icon_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash_tiny",
                            is_dir=False,
                        ),
                    ],
                ),
            ]

            file_analysis = FileAnalysis(files=files, directories=[])
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                treemap=Mock(),
                binary_analysis=[],
            )

            result = self.insight.generate(insights_input)

            # Should return None as savings are below threshold
            assert result is None

        finally:
            small_icon_path.unlink(missing_ok=True)

    def test_icon_name_matching(self):
        """Test that icon names are matched correctly with startswith logic."""
        icon1_path = self._create_test_png((200, 200), optimized=False)
        icon2_path = self._create_test_png((200, 200), optimized=False)
        icon3_path = self._create_test_png((200, 200), optimized=False)

        try:
            app_info = AppleAppInfo(
                name="TestApp",
                version="1.0",
                build="1",
                app_id="com.test.app",
                executable="TestApp",
                minimum_os_version="14.0",
                primary_icon_name="AppIcon",
                alternate_icon_names=["CustomIcon"],
            )

            files = [
                FileInfo(
                    full_path=Path("Assets.car"),
                    path="Assets.car",
                    size=500000,
                    file_type="car",
                    treemap_type=TreemapType.ASSETS,
                    hash="hash_car",
                    is_dir=False,
                    children=[
                        # Should match - starts with CustomIcon
                        FileInfo(
                            full_path=icon1_path,
                            path="Assets.car/CustomIcon-60",
                            size=icon1_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash1",
                            is_dir=False,
                        ),
                        # Should match - starts with CustomIcon
                        FileInfo(
                            full_path=icon2_path,
                            path="Assets.car/CustomIcon-60@2x",
                            size=icon2_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash2",
                            is_dir=False,
                        ),
                        # Should not match - different name
                        FileInfo(
                            full_path=icon3_path,
                            path="Assets.car/OtherIcon-60",
                            size=icon3_path.stat().st_size,
                            file_type="png",
                            treemap_type=TreemapType.ASSETS,
                            hash="hash3",
                            is_dir=False,
                        ),
                    ],
                ),
            ]

            file_analysis = FileAnalysis(files=files, directories=[])
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                treemap=Mock(),
                binary_analysis=[],
            )

            result = self.insight.generate(insights_input)

            if result:
                # Should only include CustomIcon variants
                paths = [f.file_path for f in result.optimizable_files]
                assert all("CustomIcon" in p for p in paths)
                assert not any("OtherIcon" in p for p in paths)

        finally:
            icon1_path.unlink(missing_ok=True)
            icon2_path.unlink(missing_ok=True)
            icon3_path.unlink(missing_ok=True)
