"""Tests for DuplicateFilesInsight."""

from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.common.duplicate_files import DuplicateFilesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import AppComponent, BaseAppInfo, ComponentType, FileAnalysis, FileInfo
from launchpad.size.models.insights import DuplicateFilesInsightResult
from launchpad.size.models.treemap import TreemapType


class TestDuplicateFilesInsight:
    """Test the DuplicateFilesInsight class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.insight = DuplicateFilesInsight()

    def _create_insights_input(
        self,
        files: list[FileInfo],
        *,
        app_components: list[AppComponent] | None = None,
    ) -> InsightsInput:
        """Helper method to create InsightsInput for testing."""
        file_analysis = FileAnalysis(items=files)
        return InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            binary_analysis=[],
            app_components=app_components or [],
        )

    def _apple_components(self) -> list[AppComponent]:
        return [
            AppComponent(
                component_type=ComponentType.MAIN_ARTIFACT,
                app_id="com.example.app",
                name="ExampleApp",
                path=".",
                download_size=100,
                install_size=100,
            ),
            AppComponent(
                component_type=ComponentType.APP_CLIP_ARTIFACT,
                app_id="com.example.app.clip",
                name="ExampleClip",
                path="AppClips/ExampleClip.app",
                download_size=50,
                install_size=50,
            ),
            AppComponent(
                component_type=ComponentType.WATCH_ARTIFACT,
                app_id="com.example.app.watch",
                name="ExampleWatch",
                path="Watch/ExampleWatch.app",
                download_size=50,
                install_size=50,
            ),
        ]

    def test_detects_cross_component_duplicates_when_no_components_provided(self):
        files = [
            FileInfo(
                full_path=Path("Resources/icon.png"),
                path="Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Resources/icon.png"),
                path="AppClips/ExampleClip.app/Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Watch/ExampleWatch.app/Resources/icon.png"),
                path="Watch/ExampleWatch.app/Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1
        assert result.total_savings == 4000

    def test_excludes_cross_component_duplicate_files_for_watch_and_app_clip(self):
        files = [
            FileInfo(
                full_path=Path("Resources/icon.png"),
                path="Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Resources/icon.png"),
                path="AppClips/ExampleClip.app/Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Watch/ExampleWatch.app/Resources/icon.png"),
                path="Watch/ExampleWatch.app/Resources/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files, app_components=self._apple_components())
        result = self.insight.generate(insights_input)

        assert result is None

    def test_excludes_cross_component_duplicate_directories_for_watch_and_app_clip(self):
        directories = [
            FileInfo(
                full_path=Path("Shared.bundle"),
                path="Shared.bundle",
                size=4096,
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="shared_bundle_hash",
                is_dir=True,
                size_including_children=12000,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Shared.bundle"),
                path="AppClips/ExampleClip.app/Shared.bundle",
                size=4096,
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="shared_bundle_hash",
                is_dir=True,
                size_including_children=12000,
            ),
            FileInfo(
                full_path=Path("Watch/ExampleWatch.app/Shared.bundle"),
                path="Watch/ExampleWatch.app/Shared.bundle",
                size=4096,
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="shared_bundle_hash",
                is_dir=True,
                size_including_children=12000,
            ),
        ]

        insights_input = self._create_insights_input(directories, app_components=self._apple_components())
        result = self.insight.generate(insights_input)

        assert result is None

    def test_preserves_within_component_duplicate_detection_when_components_present(self):
        files = [
            FileInfo(
                full_path=Path("Resources/a.png"),
                path="Resources/a.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="a_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/a.png"),
                path="Backup/a.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="a_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Resources/a.png"),
                path="AppClips/ExampleClip.app/Resources/a.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="a_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Resources/b.png"),
                path="AppClips/ExampleClip.app/Resources/b.png",
                size=1500,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="b_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Backup/b.png"),
                path="AppClips/ExampleClip.app/Backup/b.png",
                size=1500,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="b_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files, app_components=self._apple_components())
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 2

        a_group = next(group for group in result.groups if group.name == "a.png")
        a_paths = {entry.file_path for entry in a_group.files}
        assert a_paths == {"Resources/a.png", "Backup/a.png"}
        assert a_group.total_savings == 1000

        b_group = next(group for group in result.groups if group.name == "b.png")
        b_paths = {entry.file_path for entry in b_group.files}
        assert b_paths == {
            "AppClips/ExampleClip.app/Resources/b.png",
            "AppClips/ExampleClip.app/Backup/b.png",
        }
        assert b_group.total_savings == 1500

        assert result.total_savings == 2500

    def test_prefers_longest_matching_component_root(self):
        app_components = [
            AppComponent(
                component_type=ComponentType.MAIN_ARTIFACT,
                app_id="com.example.app",
                name="ExampleApp",
                path=".",
                download_size=100,
                install_size=100,
            ),
            AppComponent(
                component_type=ComponentType.APP_CLIP_ARTIFACT,
                app_id="com.example.app.clip",
                name="ExampleClip",
                path="AppClips/ExampleClip.app",
                download_size=50,
                install_size=50,
            ),
            AppComponent(
                component_type=ComponentType.WATCH_ARTIFACT,
                app_id="com.example.app.clip.plugin",
                name="NestedPlugin",
                path="AppClips/ExampleClip.app/PlugIns/Nested.appex",
                download_size=10,
                install_size=10,
            ),
        ]

        files = [
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/Resources/shared.bin"),
                path="AppClips/ExampleClip.app/Resources/shared.bin",
                size=1024,
                file_type="bin",
                treemap_type=TreemapType.OTHER,
                hash="shared_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("AppClips/ExampleClip.app/PlugIns/Nested.appex/Resources/shared.bin"),
                path="AppClips/ExampleClip.app/PlugIns/Nested.appex/Resources/shared.bin",
                size=1024,
                file_type="bin",
                treemap_type=TreemapType.OTHER,
                hash="shared_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files, app_components=app_components)
        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_duplicate_directories_prevents_double_counting(self):
        """
        Test that when duplicate directories are detected, individual files within
        those directories are NOT flagged separately (preventing double-counting).

        This tests the fix for the SwiftMath_SwiftMath.bundle edge case.
        """
        # Create two identical .bundle directories with identical contents
        bundle1_files = [
            FileInfo(
                full_path=Path("SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont-Bold.plist"),
                path="SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont-Bold.plist",
                size=5000,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="plist_hash_1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont.plist"),
                path="SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont.plist",
                size=4000,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="plist_hash_2",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("SwiftMath_SwiftMath.bundle/Resources/config.json"),
                path="SwiftMath_SwiftMath.bundle/Resources/config.json",
                size=3000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="json_hash_1",
                is_dir=False,
            ),
        ]

        bundle2_files = [
            FileInfo(
                full_path=Path(
                    "Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont-Bold.plist"
                ),
                path="Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont-Bold.plist",
                size=5000,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="plist_hash_1",  # Same hash as bundle1
                is_dir=False,
            ),
            FileInfo(
                full_path=Path(
                    "Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont.plist"
                ),
                path="Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/mathFonts.bundle/GenericFont.plist",
                size=4000,
                file_type="plist",
                treemap_type=TreemapType.PLISTS,
                hash="plist_hash_2",  # Same hash as bundle1
                is_dir=False,
            ),
            FileInfo(
                full_path=Path(
                    "Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/Resources/config.json"
                ),
                path="Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle/Resources/config.json",
                size=3000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="json_hash_1",  # Same hash as bundle1
                is_dir=False,
            ),
        ]

        # Add some other duplicate files outside the bundles that SHOULD be detected
        other_duplicate_files = [
            FileInfo(
                full_path=Path("Assets/icon.png"),
                path="Assets/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/icon.png"),
                path="Backup/icon.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",  # Same hash - these should be detected
                is_dir=False,
            ),
        ]

        # Create directory entries for the duplicate bundle directories
        bundle_directories = [
            # First SwiftMath_SwiftMath.bundle directory
            FileInfo(
                full_path=Path("SwiftMath_SwiftMath.bundle"),
                path="SwiftMath_SwiftMath.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=12000,  # Total content size (5000 + 4000 + 3000)
            ),
            # Second SwiftMath_SwiftMath.bundle directory (duplicate)
            FileInfo(
                full_path=Path(
                    "Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle"
                ),
                path="Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=12000,  # Total content size
            ),
        ]

        all_files = bundle_directories + bundle1_files + bundle2_files + other_duplicate_files
        insights_input = self._create_insights_input(all_files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)

        # Should have exactly 2 groups:
        # 1. The duplicate bundle directories
        # 2. The duplicate icon.png files
        assert len(result.groups) == 2

        # Find the bundle group
        bundle_group = next((g for g in result.groups if "SwiftMath_SwiftMath.bundle" in g.name), None)
        assert bundle_group is not None
        assert len(bundle_group.files) == 2  # Two bundle instances
        # Bundle savings = total size of one bundle (smaller one gets eliminated)
        bundle_size = 5000 + 4000 + 3000  # 12000 per bundle
        assert bundle_group.total_savings == bundle_size

        # Each directory should report its full content size (size_including_children),
        # not just the directory entry size (~4KB). This catches the bug where d.size
        # was used instead of d.size_including_children for directory savings.
        for file_result in bundle_group.files:
            assert file_result.total_savings == bundle_size

        # Find the icon group
        icon_group = next((g for g in result.groups if g.name == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.files) == 2  # Two icon files
        assert icon_group.total_savings == 2000  # Size of one duplicate

        # Total savings should be bundle savings + icon savings
        assert result.total_savings == bundle_size + 2000

        # Verify that individual files within the bundles are NOT flagged separately
        # None of the groups should contain the individual plist or json files
        for group in result.groups:
            for file in group.files:
                assert "GenericFont-Bold.plist" not in file.file_path
                assert "GenericFont.plist" not in file.file_path
                assert "config.json" not in file.file_path

    def test_directory_grouping_with_nested_bundles(self):
        """Test that directory grouping works correctly with nested .bundle directories."""
        files = [
            # Files in a nested bundle structure
            FileInfo(
                full_path=Path("Frameworks/MyFramework.framework/Resources.bundle/en.lproj/Localizable.strings"),
                path="Frameworks/MyFramework.framework/Resources.bundle/en.lproj/Localizable.strings",
                size=2000,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="strings_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Frameworks/MyFramework.framework/Resources.bundle/es.lproj/Localizable.strings"),
                path="Frameworks/MyFramework.framework/Resources.bundle/es.lproj/Localizable.strings",
                size=1500,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="strings_hash_es",
                is_dir=False,
            ),
            # Duplicate of the same bundle in a different location
            FileInfo(
                full_path=Path("Backup/MyFramework.framework/Resources.bundle/en.lproj/Localizable.strings"),
                path="Backup/MyFramework.framework/Resources.bundle/en.lproj/Localizable.strings",
                size=2000,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="strings_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/MyFramework.framework/Resources.bundle/es.lproj/Localizable.strings"),
                path="Backup/MyFramework.framework/Resources.bundle/es.lproj/Localizable.strings",
                size=1500,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="strings_hash_es",
                is_dir=False,
            ),
        ]

        # Add directory entries for the duplicate Resources.bundle directories
        bundle_directories = [
            # First Resources.bundle directory
            FileInfo(
                full_path=Path("Frameworks/MyFramework.framework/Resources.bundle"),
                path="Frameworks/MyFramework.framework/Resources.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=3500,  # Total content size (2000 + 1500)
            ),
            # Second Resources.bundle directory (duplicate)
            FileInfo(
                full_path=Path("Backup/MyFramework.framework/Resources.bundle"),
                path="Backup/MyFramework.framework/Resources.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=3500,  # Total content size
            ),
        ]

        all_files = files + bundle_directories
        insights_input = self._create_insights_input(all_files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1

        # Should detect the duplicate Resources.bundle directories
        group = result.groups[0]
        assert group.name == "Resources.bundle"
        assert len(group.files) == 2
        bundle_size = 2000 + 1500  # 3500 per bundle
        assert group.total_savings == bundle_size

    def test_extension_allowlist_excludes_xcprivacy_files(self):
        """Test that .xcprivacy files are excluded from duplicate detection."""
        files = [
            # Duplicate .xcprivacy files (should be ignored)
            FileInfo(
                full_path=Path("PrivacyInfo.xcprivacy"),
                path="PrivacyInfo.xcprivacy",
                size=1000,
                file_type="xcprivacy",
                treemap_type=TreemapType.OTHER,
                hash="privacy_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/PrivacyInfo.xcprivacy"),
                path="Backup/PrivacyInfo.xcprivacy",
                size=1000,
                file_type="xcprivacy",
                treemap_type=TreemapType.OTHER,
                hash="privacy_hash",  # Same hash but should be ignored
                is_dir=False,
            ),
            # Duplicate regular files (should be detected)
            FileInfo(
                full_path=Path("config.json"),
                path="config.json",
                size=2000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="config_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/config.json"),
                path="Backup/config.json",
                size=2000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="config_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1

        # Should only detect the config.json duplicates, not .xcprivacy
        group = result.groups[0]
        assert group.name == "config.json"
        assert len(group.files) == 2
        assert group.total_savings == 2000

    def test_no_duplicates_returns_none(self):
        """Test that no insight is generated when there are no duplicate files."""
        files = [
            FileInfo(
                full_path=Path("file1.png"),
                path="file1.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("file2.png"),
                path="file2.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash2",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("file3.png"),
                path="file3.png",
                size=3000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="hash3",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert result is None

    def test_files_without_hash_ignored(self):
        """Test that files without MD5 hashes are ignored."""
        files = [
            # File without hash
            FileInfo(
                full_path=Path("no_hash.png"),
                path="no_hash.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="",  # Empty hash
                is_dir=False,
            ),
            # Duplicate files with valid hashes
            FileInfo(
                full_path=Path("valid1.png"),
                path="valid1.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="valid_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("valid2.png"),
                path="valid2.png",
                size=2000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="valid_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1

        # Should only detect the files with valid hashes
        group = result.groups[0]
        assert group.name == "valid1.png"
        assert len(group.files) == 2
        assert group.total_savings == 2000

    def test_sorting_by_savings_and_filename(self):
        """Test that groups are sorted by total savings (descending), then by filename."""
        files = [
            # Small duplicate group
            FileInfo(
                full_path=Path("small1.png"),
                path="small1.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="small_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("small2.png"),
                path="small2.png",
                size=1000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="small_hash",
                is_dir=False,
            ),
            # Large duplicate group
            FileInfo(
                full_path=Path("large1.png"),
                path="large1.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="large_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("large2.png"),
                path="large2.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="large_hash",
                is_dir=False,
            ),
            # Medium duplicate group
            FileInfo(
                full_path=Path("medium1.png"),
                path="medium1.png",
                size=3000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="medium_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("medium2.png"),
                path="medium2.png",
                size=3000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="medium_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 3

        # Should be sorted by savings: large (5000), medium (3000), small (1000)
        assert result.groups[0].name == "large1.png"
        assert result.groups[0].total_savings == 5000
        assert result.groups[1].name == "medium1.png"
        assert result.groups[1].total_savings == 3000
        assert result.groups[2].name == "small1.png"
        assert result.groups[2].total_savings == 1000

    def test_container_name_preference_over_filename(self):
        """Test that container names are preferred over individual filenames when available."""
        files = [
            # Files inside a .bundle container
            FileInfo(
                full_path=Path("MyLibrary.bundle/config.json"),
                path="MyLibrary.bundle/config.json",
                size=2000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="config_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("OtherLibrary.bundle/config.json"),
                path="OtherLibrary.bundle/config.json",
                size=2000,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="config_hash",
                is_dir=False,
            ),
            # Files outside containers
            FileInfo(
                full_path=Path("standalone_config.json"),
                path="standalone_config.json",
                size=1500,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="standalone_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/standalone_config.json"),
                path="Backup/standalone_config.json",
                size=1500,
                file_type="json",
                treemap_type=TreemapType.RESOURCES,
                hash="standalone_hash",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 2

        # Find the container-based group
        container_group = next((g for g in result.groups if "bundle" not in g.name.lower()), None)
        standalone_group = next((g for g in result.groups if g.name == "standalone_config.json"), None)

        # Both groups should exist
        assert container_group is not None
        assert standalone_group is not None

    def test_empty_file_list(self):
        """Test that no insight is generated with empty file list."""
        insights_input = self._create_insights_input([])
        result = self.insight.generate(insights_input)
        assert result is None

    def test_complex_scenario_with_multiple_edge_cases(self):
        """
        Test a complex scenario combining multiple edge cases:
        - Duplicate directories with nested bundles
        - Individual file duplicates outside containers
        - Files with None full_path
        - Allowlisted extensions
        - Different container types
        """
        files = [
            # Duplicate .bundle directories (should be grouped as directories)
            FileInfo(
                full_path=Path("Framework1.framework/Resources.bundle/file1.txt"),
                path="Framework1.framework/Resources.bundle/file1.txt",
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.RESOURCES,
                hash="bundle_file1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Framework1.framework/Resources.bundle/file2.txt"),
                path="Framework1.framework/Resources.bundle/file2.txt",
                size=2000,
                file_type="txt",
                treemap_type=TreemapType.RESOURCES,
                hash="bundle_file2",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Framework2.framework/Resources.bundle/file1.txt"),
                path="Framework2.framework/Resources.bundle/file1.txt",
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.RESOURCES,
                hash="bundle_file1",  # Same content as Framework1
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Framework2.framework/Resources.bundle/file2.txt"),
                path="Framework2.framework/Resources.bundle/file2.txt",
                size=2000,
                file_type="txt",
                treemap_type=TreemapType.RESOURCES,
                hash="bundle_file2",  # Same content as Framework1
                is_dir=False,
            ),
            # Individual duplicates outside containers (should be detected separately)
            FileInfo(
                full_path=Path("Assets/icon.png"),
                path="Assets/icon.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/icon.png"),
                path="Backup/icon.png",
                size=5000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="icon_hash",
                is_dir=False,
            ),
            # Files with None full_path (should still be processed)
            FileInfo(
                full_path=None,
                path="Assets.car/embedded_icon.png",
                size=3000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="embedded_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=None,
                path="Backup.car/embedded_icon.png",
                size=3000,
                file_type="png",
                treemap_type=TreemapType.ASSETS,
                hash="embedded_hash",
                is_dir=False,
            ),
            # Allowlisted files (should be ignored)
            FileInfo(
                full_path=Path("PrivacyInfo.xcprivacy"),
                path="PrivacyInfo.xcprivacy",
                size=1000,
                file_type="xcprivacy",
                treemap_type=TreemapType.OTHER,
                hash="privacy_hash",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Backup/PrivacyInfo.xcprivacy"),
                path="Backup/PrivacyInfo.xcprivacy",
                size=1000,
                file_type="xcprivacy",
                treemap_type=TreemapType.OTHER,
                hash="privacy_hash",  # Should be ignored
                is_dir=False,
            ),
        ]

        # Add directory entries for the duplicate Resources.bundle directories
        bundle_directories = [
            # First Resources.bundle directory
            FileInfo(
                full_path=Path("Framework1.framework/Resources.bundle"),
                path="Framework1.framework/Resources.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=3000,  # Total content size (1000 + 2000)
            ),
            # Second Resources.bundle directory (duplicate)
            FileInfo(
                full_path=Path("Framework2.framework/Resources.bundle"),
                path="Framework2.framework/Resources.bundle",
                size=4096,  # Directory entry size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
                size_including_children=3000,  # Total content size
            ),
        ]

        all_files = files + bundle_directories
        insights_input = self._create_insights_input(all_files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)

        # Should have exactly 3 groups:
        # 1. Duplicate Resources.bundle directories (largest savings)
        # 2. Duplicate icon.png files
        # 3. Duplicate embedded_icon.png files
        assert len(result.groups) == 3

        # Verify the bundle group
        bundle_group = next((g for g in result.groups if g.name == "Resources.bundle"), None)
        assert bundle_group is not None
        assert len(bundle_group.files) == 2
        bundle_size = 1000 + 2000  # 3000 per bundle
        assert bundle_group.total_savings == bundle_size

        # Verify the icon group
        icon_group = next((g for g in result.groups if g.name == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.files) == 2
        assert icon_group.total_savings == 5000

        # Verify the embedded icon group
        embedded_group = next((g for g in result.groups if g.name == "embedded_icon.png"), None)
        assert embedded_group is not None
        assert len(embedded_group.files) == 2
        assert embedded_group.total_savings == 3000

        # Verify total savings
        expected_total = bundle_size + 5000 + 3000  # 11000
        assert result.total_savings == expected_total

        # Verify that .xcprivacy files were ignored (no group for them)
        privacy_group = next((g for g in result.groups if "xcprivacy" in g.name), None)
        assert privacy_group is None

    def test_nested_children_are_flattened_for_duplicate_detection(self):
        """Test that nested children (e.g., assets inside .car files) are included in duplicate detection."""
        files = [
            # Parent .car file with nested children
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=10000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="car_hash",
                is_dir=False,
                children=[
                    FileInfo(
                        full_path=Path("Assets.car/icon.png"),
                        path="Assets.car/icon.png",
                        size=2000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="nested_icon_hash",
                        is_dir=False,
                        children=[],
                    ),
                    FileInfo(
                        full_path=Path("Assets.car/logo.png"),
                        path="Assets.car/logo.png",
                        size=3000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="nested_logo_hash",
                        is_dir=False,
                        children=[],
                    ),
                ],
            ),
            # Another .car file with duplicate nested assets
            FileInfo(
                full_path=Path("Resources.bundle/Assets.car"),
                path="Resources.bundle/Assets.car",
                size=8000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="different_car_hash",
                is_dir=False,
                children=[
                    FileInfo(
                        full_path=Path("Resources.bundle/Assets.car/icon.png"),
                        path="Resources.bundle/Assets.car/icon.png",
                        size=2000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="nested_icon_hash",  # Same hash as Assets.car/icon.png
                        is_dir=False,
                        children=[],
                    ),
                ],
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1

        # Should detect the duplicate nested icon.png files
        group = result.groups[0]
        assert group.name == "icon.png"
        assert len(group.files) == 2
        assert group.total_savings == 2000

        # Verify both paths are the nested ones, not the parent .car files
        paths = {f.file_path for f in group.files}
        assert "Assets.car/icon.png" in paths
        assert "Resources.bundle/Assets.car/icon.png" in paths

    def test_duplicate_car_files_dont_double_count_children(self):
        """
        Test that when entire Assets.car files are duplicates, we only report the
        .car files as duplicates, not their individual nested children (prevents double-counting).
        """
        files = [
            # First Assets.car with children
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=10000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="duplicate_car_hash",
                is_dir=False,
                children=[
                    FileInfo(
                        full_path=Path("Assets.car/icon.png"),
                        path="Assets.car/icon.png",
                        size=2000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="icon_hash_inside_car",
                        is_dir=False,
                        children=[],
                    ),
                    FileInfo(
                        full_path=Path("Assets.car/logo.png"),
                        path="Assets.car/logo.png",
                        size=3000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="logo_hash_inside_car",
                        is_dir=False,
                        children=[],
                    ),
                ],
            ),
            # Duplicate Assets.car with same children
            FileInfo(
                full_path=Path("Backup/Assets.car"),
                path="Backup/Assets.car",
                size=10000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="duplicate_car_hash",  # Same hash as first .car
                is_dir=False,
                children=[
                    FileInfo(
                        full_path=Path("Backup/Assets.car/icon.png"),
                        path="Backup/Assets.car/icon.png",
                        size=2000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="icon_hash_inside_car",  # Same hash as first icon
                        is_dir=False,
                        children=[],
                    ),
                    FileInfo(
                        full_path=Path("Backup/Assets.car/logo.png"),
                        path="Backup/Assets.car/logo.png",
                        size=3000,
                        file_type="png",
                        treemap_type=TreemapType.ASSETS,
                        hash="logo_hash_inside_car",  # Same hash as first logo
                        is_dir=False,
                        children=[],
                    ),
                ],
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)

        # Should only have 1 group: the duplicate Assets.car files
        # The nested children should NOT be flagged separately
        assert len(result.groups) == 1

        group = result.groups[0]
        assert group.name == "Assets.car"
        assert len(group.files) == 2
        assert group.total_savings == 10000

        # Verify the group contains the .car files, not their children
        paths = {f.file_path for f in group.files}
        assert "Assets.car" in paths
        assert "Backup/Assets.car" in paths

        # Verify no nested children appear in the results
        for g in result.groups:
            for f in g.files:
                assert "icon.png" not in f.file_path
                assert "logo.png" not in f.file_path
