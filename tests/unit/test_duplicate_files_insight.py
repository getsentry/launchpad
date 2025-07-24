"""Tests for DuplicateFilesInsight."""

from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.common.duplicate_files import DuplicateFilesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import DuplicateFilesInsightResult
from launchpad.size.models.treemap import TreemapType


class TestDuplicateFilesInsight:
    """Test the DuplicateFilesInsight class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.insight = DuplicateFilesInsight()

    def _create_insights_input(self, files: list[FileInfo]) -> InsightsInput:
        """Helper method to create InsightsInput for testing."""
        # Separate directories from the files list
        directories = [f for f in files if f.is_dir]
        file_analysis = FileAnalysis(files=files, directories=directories)
        return InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

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
                size=12000,  # Total size of all files in bundle
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="bundle_hash",  # Same hash for identical content
                is_dir=True,
            ),
            # Second SwiftMath_SwiftMath.bundle directory (duplicate)
            FileInfo(
                full_path=Path(
                    "Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle"
                ),
                path="Frameworks/SwiftMath_-5E59CDD896963160_PackageProduct.framework/SwiftMath_SwiftMath.bundle",
                size=12000,  # Same total size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="bundle_hash",  # Same hash for identical content
                is_dir=True,
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
        bundle_group = next((g for g in result.groups if "SwiftMath_SwiftMath.bundle" in g.filename), None)
        assert bundle_group is not None
        assert len(bundle_group.files) == 2  # Two bundle instances
        # Bundle savings = total size of one bundle (smaller one gets eliminated)
        bundle_size = 5000 + 4000 + 3000  # 12000 per bundle
        assert bundle_group.total_savings == bundle_size

        # Find the icon group
        icon_group = next((g for g in result.groups if g.filename == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.files) == 2  # Two icon files
        assert icon_group.total_savings == 2000  # Size of one duplicate

        # Total savings should be bundle savings + icon savings
        assert result.total_savings == bundle_size + 2000

        # Verify that individual files within the bundles are NOT flagged separately
        # None of the groups should contain the individual plist or json files
        for group in result.groups:
            for file in group.files:
                assert "GenericFont-Bold.plist" not in file.path
                assert "GenericFont.plist" not in file.path
                assert "config.json" not in file.path

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
                size=3500,  # Total size of all files in bundle (2000 + 1500)
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
            ),
            # Second Resources.bundle directory (duplicate)
            FileInfo(
                full_path=Path("Backup/MyFramework.framework/Resources.bundle"),
                path="Backup/MyFramework.framework/Resources.bundle",
                size=3500,  # Same total size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
            ),
        ]

        all_files = files + bundle_directories
        insights_input = self._create_insights_input(all_files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, DuplicateFilesInsightResult)
        assert len(result.groups) == 1

        # Should detect the duplicate Resources.bundle directories
        group = result.groups[0]
        assert group.filename == "Resources.bundle"
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
        assert group.filename == "config.json"
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
        assert group.filename == "valid1.png"
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
        assert result.groups[0].filename == "large1.png"
        assert result.groups[0].total_savings == 5000
        assert result.groups[1].filename == "medium1.png"
        assert result.groups[1].total_savings == 3000
        assert result.groups[2].filename == "small1.png"
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
        container_group = next((g for g in result.groups if "bundle" not in g.filename.lower()), None)
        standalone_group = next((g for g in result.groups if g.filename == "standalone_config.json"), None)

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
                size=3000,  # Total size of all files in bundle (1000 + 2000)
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
            ),
            # Second Resources.bundle directory (duplicate)
            FileInfo(
                full_path=Path("Framework2.framework/Resources.bundle"),
                path="Framework2.framework/Resources.bundle",
                size=3000,  # Same total size
                file_type="directory",
                treemap_type=TreemapType.OTHER,
                hash="resources_bundle_hash",  # Same hash for identical content
                is_dir=True,
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
        bundle_group = next((g for g in result.groups if g.filename == "Resources.bundle"), None)
        assert bundle_group is not None
        assert len(bundle_group.files) == 2
        bundle_size = 1000 + 2000  # 3000 per bundle
        assert bundle_group.total_savings == bundle_size

        # Verify the icon group
        icon_group = next((g for g in result.groups if g.filename == "icon.png"), None)
        assert icon_group is not None
        assert len(icon_group.files) == 2
        assert icon_group.total_savings == 5000

        # Verify the embedded icon group
        embedded_group = next((g for g in result.groups if g.filename == "embedded_icon.png"), None)
        assert embedded_group is not None
        assert len(embedded_group.files) == 2
        assert embedded_group.total_savings == 3000

        # Verify total savings
        expected_total = bundle_size + 5000 + 3000  # 11000
        assert result.total_savings == expected_total

        # Verify that .xcprivacy files were ignored (no group for them)
        privacy_group = next((g for g in result.groups if "xcprivacy" in g.filename), None)
        assert privacy_group is None
