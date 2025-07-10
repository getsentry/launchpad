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
            full_path="en.lproj/Localizable.strings",
            path="en.lproj/Localizable.strings",
            size=60 * 1024,  # 60KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash1",
        )
        localized_file_2 = FileInfo(
            full_path="es.lproj/Localizable.strings",
            path="es.lproj/Localizable.strings",
            size=50 * 1024,  # 50KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash2",
        )
        # Non-localized file that should be ignored
        other_file = FileInfo(
            full_path="assets/image.png",
            path="assets/image.png",
            size=1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash3",
        )

        file_analysis = FileAnalysis(files=[localized_file_1, localized_file_2, other_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        assert len(result.files) == 2
        assert result.total_savings == 110 * 1024  # 110KB total
        assert result.files[0].path == "en.lproj/Localizable.strings"
        assert result.files[1].path == "es.lproj/Localizable.strings"

    def test_generate_with_small_localized_strings(self):
        """Test that no insight is generated when total size is below 100KB threshold."""
        # Create localized strings files that don't exceed 100KB total
        localized_file_1 = FileInfo(
            full_path="en.lproj/Localizable.strings",
            path="en.lproj/Localizable.strings",
            size=40 * 1024,  # 40KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash1",
        )
        localized_file_2 = FileInfo(
            full_path="es.lproj/Localizable.strings",
            path="es.lproj/Localizable.strings",
            size=30 * 1024,  # 30KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[localized_file_1, localized_file_2])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # Should return None when below threshold

    def test_generate_with_exactly_threshold_size(self):
        """Test that insight is generated when total size exactly equals 100KB threshold."""
        localized_file = FileInfo(
            full_path="en.lproj/Localizable.strings",
            path="en.lproj/Localizable.strings",
            size=100 * 1024,  # Exactly 100KB
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[localized_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None  # Should return None when exactly at threshold

    def test_generate_with_no_localized_strings(self):
        """Test that no insight is generated when no localized strings files exist."""
        other_file_1 = FileInfo(
            full_path="assets/image.png",
            path="assets/image.png",
            size=1024,
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        other_file_2 = FileInfo(
            full_path="Info.plist",
            path="Info.plist",
            size=2048,
            file_type="plist",
            treemap_type=TreemapType.PLISTS,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[other_file_1, other_file_2])

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
        file_analysis = FileAnalysis(files=[])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_ignores_non_localizable_strings(self):
        """Test that only Localizable.strings files are considered, not other .strings files."""
        localized_file = FileInfo(
            full_path="en.lproj/Localizable.strings",
            path="en.lproj/Localizable.strings",
            size=150 * 1024,  # 150KB - should trigger insight
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash1",
        )
        other_strings_file = FileInfo(
            full_path="en.lproj/Other.strings",
            path="en.lproj/Other.strings",
            size=50 * 1024,  # 50KB - should be ignored
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[localized_file, other_strings_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        assert len(result.files) == 1
        assert result.files[0].path == "en.lproj/Localizable.strings"
        assert result.total_savings == 150 * 1024  # Only the Localizable.strings file

    def test_generate_ignores_non_lproj_localizable_strings(self):
        """Test that Localizable.strings files outside .lproj directories are ignored."""
        valid_localized_file = FileInfo(
            full_path="en.lproj/Localizable.strings",
            path="en.lproj/Localizable.strings",
            size=150 * 1024,  # 150KB - should be included
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash1",
        )
        invalid_localized_file = FileInfo(
            full_path="Localizable.strings",  # Not in .lproj directory
            path="Localizable.strings",
            size=50 * 1024,  # 50KB - should be ignored
            file_type="strings",
            treemap_type=TreemapType.RESOURCES,
            hash_md5="hash2",
        )

        file_analysis = FileAnalysis(files=[valid_localized_file, invalid_localized_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, LocalizedStringInsightResult)
        assert len(result.files) == 1
        assert result.files[0].path == "en.lproj/Localizable.strings"
        assert result.total_savings == 150 * 1024  # Only the valid file
