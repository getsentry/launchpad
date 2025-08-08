from pathlib import Path
from unittest.mock import Mock

from launchpad.size.insights.apple.localized_strings import LocalizedStringsInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import LocalizedStringInsightResult
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType


class TestLocalizedStringsInsight:
    def setup_method(self):
        self.insight = LocalizedStringsInsight()

    def test_generate_with_large_localized_strings(self):
        """Test that insight is generated when total size exceeds 100KB threshold."""
        # Create localized strings files that exceed 100KB total
        localized_file_1 = FileInfo(
            full_path=Path("en.lproj/Localizable.strings"),
            path="en.lproj/Localizable.strings",
            size=150 * 1024,  # 150KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash1",
            is_dir=False,
        )
        localized_file_2 = FileInfo(
            full_path=Path("es.lproj/Localizable.strings"),
            path="es.lproj/Localizable.strings",
            size=60 * 1024,  # 60KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash2",
            is_dir=False,
        )
        # Non-localized file that should be ignored
        other_file = FileInfo(
            full_path=Path("assets/image.png"),
            path="assets/image.png",
            size=1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash3",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[localized_file_1, localized_file_2, other_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        # Total savings should be 50% of the total file size (210KB * 0.5 = 105KB)
        expected_total_savings = int((150 + 60) * 1024 * 0.5)
        assert result.total_savings == expected_total_savings

    def test_generate_with_small_localized_strings(self):
        """Test that no insight is generated when estimated savings is below 100KB threshold."""
        # Create localized strings files where estimated savings (50%) don't exceed 100KB
        localized_file_1 = FileInfo(
            full_path=Path("en.lproj/Localizable.strings"),
            path="en.lproj/Localizable.strings",
            size=60 * 1024,  # 60KB * 0.5 = 30KB savings
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash1",
            is_dir=False,
        )
        localized_file_2 = FileInfo(
            full_path=Path("es.lproj/Localizable.strings"),
            path="es.lproj/Localizable.strings",
            size=50 * 1024,  # 50KB * 0.5 = 25KB savings (total 55KB < 100KB threshold)
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[localized_file_1, localized_file_2], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # Should return None when estimated savings below threshold

    def test_generate_with_exactly_threshold_size(self):
        """Test that insight is generated when estimated savings exceeds 100KB threshold."""
        # Need 200KB to get exactly 100KB savings (200KB * 0.5 = 100KB)
        localized_file = FileInfo(
            full_path=Path("en.lproj/Localizable.strings"),
            path="en.lproj/Localizable.strings",
            size=200 * 1024,  # 200KB * 0.5 = 100KB savings
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash1",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[localized_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # Should return None when exactly at threshold (100KB, not >100KB)

    def test_generate_with_no_localized_strings(self):
        """Test that no insight is generated when no localized strings files exist."""
        other_file_1 = FileInfo(
            full_path=Path("assets/image.png"),
            path="assets/image.png",
            size=1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash="hash1",
            is_dir=False,
        )
        other_file_2 = FileInfo(
            full_path=Path("Info.plist"),
            path="Info.plist",
            size=2048,
            file_type="plist",
            treemap_type=TreemapType.PLISTS,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[other_file_1, other_file_2], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_empty_file_list(self):
        """Test that no insight is generated with empty file list."""
        file_analysis = FileAnalysis(files=[], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_includes_all_strings_files_except_denylisted(self):
        """Test that all .strings files in .lproj directories are considered, except denylisted ones."""
        localizable_file = FileInfo(
            full_path=Path("en.lproj/Localizable.strings"),
            path="en.lproj/Localizable.strings",
            size=150 * 1024,  # 150KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash1",
            is_dir=False,
        )
        infoplist_file = FileInfo(
            full_path=Path("en.lproj/InfoPlist.strings"),
            path="en.lproj/InfoPlist.strings",
            size=100 * 1024,  # 100KB - should be included
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash2",
            is_dir=False,
        )
        launchscreen_file = FileInfo(
            full_path=Path("en.lproj/LaunchScreen.strings"),
            path="en.lproj/LaunchScreen.strings",
            size=30 * 1024,  # 30KB - should be ignored (in denylist)
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash3",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[localizable_file, infoplist_file, launchscreen_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        # Should include localizable and infoplist, but not launchscreen
        # Total size: (150KB + 100KB) * 0.5 = 125KB savings
        expected_savings = int((150 + 100) * 1024 * 0.5)
        assert result.total_savings == expected_savings

    def test_generate_ignores_non_lproj_localizable_strings(self):
        """Test that Localizable.strings files outside .lproj directories are ignored."""
        valid_localized_file = FileInfo(
            full_path=Path("en.lproj/Localizable.strings"),
            path="en.lproj/Localizable.strings",
            size=250 * 1024,  # 250KB - should be included
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash1",
            is_dir=False,
        )
        invalid_localized_file = FileInfo(
            full_path=Path("Localizable.strings"),  # Not in .lproj directory
            path="Localizable.strings",
            size=50 * 1024,  # 50KB - should be ignored
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash="hash2",
            is_dir=False,
        )

        file_analysis = FileAnalysis(files=[valid_localized_file, invalid_localized_file], directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        # Only the valid file should be included: 250KB * 0.5 = 125KB savings
        expected_savings = int(250 * 1024 * 0.5)
        assert result.total_savings == expected_savings

    def test_regex_pattern_matching(self):
        """Test that the regex pattern correctly matches .lproj/.strings files."""
        # Valid patterns that should match
        valid_files = [
            FileInfo(
                full_path=Path("en.lproj/Localizable.strings"),
                path="en.lproj/Localizable.strings",
                size=250 * 1024,  # Large enough to trigger insight after 0.5 ratio
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash1",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("Base.lproj/InfoPlist.strings"),
                path="Base.lproj/InfoPlist.strings",
                size=30 * 1024,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash2",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("pt-BR.lproj/Custom.strings"),
                path="pt-BR.lproj/Custom.strings",
                size=20 * 1024,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash3",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("some/path/en.lproj/file.strings"),  # Valid: frameworks can have .lproj dirs
                path="some/path/en.lproj/file.strings",
                size=50 * 1024,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash5",
                is_dir=False,
            ),
        ]

        # Invalid patterns that should NOT match
        invalid_files = [
            FileInfo(
                full_path=Path("Localizable.strings"),  # Not in .lproj
                path="Localizable.strings",
                size=50 * 1024,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash4",
                is_dir=False,
            ),
            FileInfo(
                full_path=Path("en.lproj/subdir/file.strings"),  # Has subdirectory in .lproj
                path="en.lproj/subdir/file.strings",
                size=50 * 1024,
                file_type="strings",
                treemap_type=TreemapType.RESOURCES,
                hash="hash6",
                is_dir=False,
            ),
        ]

        all_files = valid_files + invalid_files
        file_analysis = FileAnalysis(files=all_files, directories=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        # Should include valid files: (250 + 30 + 20 + 50) * 1024 * 0.5 = 175KB
        # Note: some/path/en.lproj/file.strings is valid (frameworks can have .lproj dirs)
        expected_savings = int((250 + 30 + 20 + 50) * 1024 * 0.5)
        assert result.total_savings == expected_savings
