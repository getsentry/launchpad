"""Tests for UnnecessaryFilesInsight."""

from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.apple.unnecessary_files import UnnecessaryFilesInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import UnnecessaryFilesInsightResult
from launchpad.size.models.treemap import TreemapType


class TestUnnecessaryFilesInsight:
    """Test the UnnecessaryFilesInsight class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.insight = UnnecessaryFilesInsight()

    def _create_insights_input(self, files: list[FileInfo]) -> InsightsInput:
        """Helper method to create InsightsInput for testing."""
        file_analysis = FileAnalysis(files=files, directories=[])
        return InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

    def test_generate_with_unnecessary_files(self):
        """Test that insight is generated when unnecessary files are found."""
        unnecessary_files = [
            # README file
            FileInfo(
                full_path=Path("README.md"),
                path="README.md",
                size=5000,
                file_type="md",
                treemap_type=TreemapType.OTHER,
                hash="hash1",
                is_dir=False,
            ),
            # Shell script
            FileInfo(
                full_path=Path("scripts/build.sh"),
                path="scripts/build.sh",
                size=3000,
                file_type="sh",
                treemap_type=TreemapType.OTHER,
                hash="hash2",
                is_dir=False,
            ),
            # Xcode config
            FileInfo(
                full_path=Path("Config/Debug.xcconfig"),
                path="Config/Debug.xcconfig",
                size=2000,
                file_type="xcconfig",
                treemap_type=TreemapType.OTHER,
                hash="hash3",
                is_dir=False,
            ),
        ]

        necessary_files = [
            # Regular app file
            FileInfo(
                full_path=Path("MyApp"),
                path="MyApp",
                size=100000,
                file_type="",
                treemap_type=TreemapType.EXECUTABLES,
                hash="hash4",
                is_dir=False,
            ),
            # Asset file
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=50000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="hash5",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(unnecessary_files + necessary_files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, UnnecessaryFilesInsightResult)
        assert len(result.files) == 3
        assert result.total_savings == 10000  # 5000 + 3000 + 2000

        # Files should be sorted by size descending
        assert result.files[0].total_savings == 5000  # README.md
        assert result.files[1].total_savings == 3000  # build.sh
        assert result.files[2].total_savings == 2000  # Debug.xcconfig

    def test_generate_with_no_unnecessary_files(self):
        """Test that no insight is generated when no unnecessary files are found."""
        necessary_files = [
            FileInfo(
                full_path=Path("MyApp"),
                path="MyApp",
                size=100000,
                file_type="",
                treemap_type=TreemapType.EXECUTABLES,
                hash="hash1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Assets.car"),
                path="Assets.car",
                size=50000,
                file_type="car",
                treemap_type=TreemapType.ASSETS,
                hash="hash2",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(necessary_files)
        result = self.insight.generate(insights_input)
        assert result is None

    def test_generate_with_empty_file_list(self):
        """Test that no insight is generated with empty file list."""
        insights_input = self._create_insights_input([])
        result = self.insight.generate(insights_input)
        assert result is None

    def test_pattern_matching_readme_files(self):
        """Test that various README file patterns are matched."""
        readme_files = [
            "README",
            "README.md",
            "README.txt",
            "READMEfirst.txt",
        ]

        for filename in readme_files:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is not None, f"Should match {filename}"
            assert len(result.files) == 1
            assert result.files[0].file_path == filename

    def test_pattern_matching_changelog_files(self):
        """Test that various CHANGELOG file patterns are matched."""
        changelog_files = [
            "CHANGELOG",
            "CHANGELOG.md",
            "CHANGELOG.txt",
            "CHANGELOGnotes.md",
        ]

        for filename in changelog_files:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is not None, f"Should match {filename}"
            assert len(result.files) == 1
            assert result.files[0].file_path == filename

    def test_pattern_matching_shell_scripts(self):
        """Test that shell script patterns are matched."""
        shell_files = [
            "build.sh",
            "deploy.sh",
            "test.sh",
            "scripts/setup.sh",
        ]

        for filename in shell_files:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="sh",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is not None, f"Should match {filename}"
            assert len(result.files) == 1
            assert result.files[0].file_path == filename

    def test_pattern_matching_development_files(self):
        """Test that various development files are matched."""
        dev_files = [
            "app.mobileprovision",
            "BUILD.bazel",
            "Config.xcconfig",
            "MyModule.swiftmodule",
            "module.modulemap",
            "symbols.bcsymbolmap",
            "exported_symbols",
            "prefix.pch",
            "TestPlan.xctestplan",
        ]

        for filename in dev_files:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type=filename.split(".")[-1] if "." in filename else "",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is not None, f"Should match {filename}"
            assert len(result.files) == 1
            assert result.files[0].file_path == filename

    def test_pattern_matching_exact_filenames(self):
        """Test that exact filename matches work correctly."""
        # These should match exactly
        exact_matches = [
            "module.modulemap",
            "exported_symbols",
        ]

        for filename in exact_matches:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is not None, f"Should match exact filename {filename}"
            assert len(result.files) == 1
            assert result.files[0].file_path == filename

        # These should NOT match (similar but not exact)
        non_matches = [
            "my_module.modulemap",  # Not exact match
            "exported_symbols_list",  # Not exact match
        ]

        for filename in non_matches:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            assert result is None, f"Should not match {filename}"

    def test_pattern_matching_case_sensitivity(self):
        """Test that pattern matching is case sensitive where appropriate."""
        # These should not match due to case differences
        case_mismatches = [
            "readme.md",  # lowercase
            "changelog.txt",  # lowercase
            "authors",  # lowercase
        ]

        for filename in case_mismatches:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type="txt",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)
            # Should not match due to case sensitivity
            assert result is None, f"Should not match case-different {filename}"

    def test_pattern_matching_file_extensions(self):
        """Test that file extension patterns work correctly."""
        extension_files = [
            ("script.sh", True),
            ("config.xcconfig", True),
            ("module.swiftmodule", True),
            ("symbols.bcsymbolmap", True),
            ("header.pch", True),
            ("plan.xctestplan", True),
            ("provision.mobileprovision", True),
            ("BUILD.bazel", True),
            # Files that should not match
            ("file.txt", False),
            ("image.png", False),
            ("app.swift", False),
        ]

        for filename, should_match in extension_files:
            file_info = FileInfo(
                full_path=Path(filename),
                path=filename,
                size=1000,
                file_type=filename.split(".")[-1] if "." in filename else "",
                treemap_type=TreemapType.OTHER,
                hash="hash",
                is_dir=False,
            )
            insights_input = self._create_insights_input([file_info])
            result = self.insight.generate(insights_input)

            if should_match:
                assert result is not None, f"Should match {filename}"
                assert len(result.files) == 1
                assert result.files[0].file_path == filename
            else:
                assert result is None, f"Should not match {filename}"

    def test_files_sorted_by_size_descending(self):
        """Test that unnecessary files are sorted by size in descending order."""
        files = [
            FileInfo(
                full_path=Path("small.sh"),
                path="small.sh",
                size=1000,
                file_type="sh",
                treemap_type=TreemapType.OTHER,
                hash="hash1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("README.md"),
                path="README.md",
                size=5000,
                file_type="md",
                treemap_type=TreemapType.OTHER,
                hash="hash2",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("medium.xcconfig"),
                path="medium.xcconfig",
                size=3000,
                file_type="xcconfig",
                treemap_type=TreemapType.OTHER,
                hash="hash3",
                is_dir=False,
            ),
        ]

        insights_input = self._create_insights_input(files)
        result = self.insight.generate(insights_input)

        assert isinstance(result, UnnecessaryFilesInsightResult)
        assert len(result.files) == 3

        # Should be sorted by size descending
        assert result.files[0].total_savings == 5000  # README.md
        assert result.files[1].total_savings == 3000  # medium.xcconfig
        assert result.files[2].total_savings == 1000  # small.sh
