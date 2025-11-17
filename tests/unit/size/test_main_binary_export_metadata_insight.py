from pathlib import Path

from launchpad.size.insights.apple.main_binary_export_metadata import MainBinaryExportMetadataInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import LinkEditInfo, MachOBinaryAnalysis
from launchpad.size.models.common import BaseAppInfo, FileAnalysis
from launchpad.size.models.insights import MainBinaryExportMetadataResult


class TestMainBinaryExportMetadataInsight:
    def setup_method(self):
        self.insight = MainBinaryExportMetadataInsight()

    def test_generate_with_main_binary_and_dyld_exports_trie(self):
        """Test that insight is generated when main binary has export trie data."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=5000),
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 5000

    def test_generate_with_main_binary_without_dyld_exports_trie(self):
        """Test that no insight is generated when main binary has no linkedit_info."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=None,  # No linkedit_info
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_no_main_binary(self):
        """Test that no insight is generated when there is no main binary."""
        framework_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=False,  # Not a main binary
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=5000),  # Has export trie but not main binary
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_main_binary_but_empty_export_trie(self):
        """Test that no insight is generated when main binary has zero-size export trie."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=0),  # Zero-size export trie
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_empty_binary_analysis_list(self):
        """Test that no insight is generated when binary_analysis list is empty."""
        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[],  # Empty list
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_multiple_binaries_one_main(self):
        """Test that insight works correctly when there are multiple binaries with one main."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=150000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=8000),
        )

        # Create framework binary (non-main)
        framework_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=3000),  # Framework also has export trie but won't be included
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis, main_binary_analysis],  # Framework first, main second
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 8000

    def test_generate_with_export_trie_below_threshold(self):
        """Test that insight handles export trie size below the minimum threshold."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=512),  # Below MIN_EXPORTS_THRESHOLD (1024)
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_export_trie_at_threshold(self):
        """Test that insight is generated when export trie size is exactly at the minimum threshold."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
            linkedit_info=LinkEditInfo(export_trie_size=1024),  # Exactly at MIN_EXPORTS_THRESHOLD
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(items=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 1024
