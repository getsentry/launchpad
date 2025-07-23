from pathlib import Path

from launchpad.size.insights.apple.main_binary_export_metadata import MainBinaryExportMetadataInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, MainBinaryExportMetadataResult
from launchpad.size.models.binary_component import BinaryAnalysis, BinaryComponent, BinaryTag
from launchpad.size.models.common import BaseAppInfo, FileAnalysis


class TestMainBinaryExportMetadataInsight:
    def setup_method(self):
        self.insight = MainBinaryExportMetadataInsight()

    def test_generate_with_main_binary_and_dyld_exports_trie(self):
        """Test that insight is generated when main binary has dyld_exports_trie component."""
        dyld_exports_trie_component = BinaryComponent(
            name="dyld_exports_trie", size=5000, tag=BinaryTag.DYLD_EXPORTS, description="DYLD exports trie section"
        )

        other_component = BinaryComponent(
            name="__text", size=50000, tag=BinaryTag.TEXT_SEGMENT, description="Text segment"
        )

        binary_analysis = BinaryAnalysis(
            file_path="MyApp", total_size=100000, components=[other_component, dyld_exports_trie_component]
        )

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path="MyApp",
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 50000, "__data": 10000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=binary_analysis,
            is_main_binary=True,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 5000

    def test_generate_with_main_binary_without_dyld_exports_trie(self):
        """Test that no insight is generated when main binary lacks dyld_exports_trie component."""
        other_component = BinaryComponent(
            name="__text", size=50000, tag=BinaryTag.TEXT_SEGMENT, description="Text segment"
        )

        binary_analysis = BinaryAnalysis(
            file_path="MyApp",
            total_size=100000,
            components=[other_component],  # No dyld_exports_trie
        )

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path="MyApp",
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 50000, "__data": 10000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=binary_analysis,
            is_main_binary=True,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_no_main_binary(self):
        """Test that no insight is generated when there is no main binary."""
        framework_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path="Frameworks/MyFramework.framework/MyFramework",
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 30000, "__data": 5000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=None,
            is_main_binary=False,  # Not a main binary
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_main_binary_but_no_binary_analysis(self):
        """Test that no insight is generated when main binary has no binary_analysis."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path="MyApp",
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 50000, "__data": 10000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=None,  # No binary analysis
            is_main_binary=True,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_empty_binary_analysis_list(self):
        """Test that no insight is generated when binary_analysis list is empty."""
        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[],  # Empty list
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_multiple_binaries_one_main(self):
        """Test that insight works correctly when there are multiple binaries with one main."""
        # Create dyld_exports_trie component for main binary
        dyld_exports_trie_component = BinaryComponent(
            name="dyld_exports_trie", size=8000, tag=BinaryTag.DYLD_EXPORTS, description="DYLD exports trie section"
        )

        main_binary_analysis_data = BinaryAnalysis(
            file_path="MyApp", total_size=150000, components=[dyld_exports_trie_component]
        )

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path="MyApp",
            executable_size=150000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 80000, "__data": 20000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=main_binary_analysis_data,
            is_main_binary=True,
        )

        # Create framework binary (non-main)
        framework_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path="Frameworks/MyFramework.framework/MyFramework",
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 30000, "__data": 5000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=None,
            is_main_binary=False,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis, main_binary_analysis],  # Framework first, main second
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 8000

    def test_generate_with_non_macho_binary_analysis(self):
        """Test that insight ignores non-MachO binary analyses."""
        from launchpad.size.models.common import BaseBinaryAnalysis

        non_macho_binary = BaseBinaryAnalysis(
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 30000},
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[non_macho_binary],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_dyld_exports_trie_zero_size(self):
        """Test that insight handles dyld_exports_trie component with zero size."""
        dyld_exports_trie_component = BinaryComponent(
            name="dyld_exports_trie",
            size=0,  # Zero size
            tag=BinaryTag.DYLD_EXPORTS,
            description="Empty DYLD exports trie section",
        )

        binary_analysis = BinaryAnalysis(file_path="MyApp", total_size=100000, components=[dyld_exports_trie_component])

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path="MyApp",
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            sections={"__text": 50000, "__data": 10000},
            symbol_info=None,
            swift_metadata=None,
            binary_analysis=binary_analysis,
            is_main_binary=True,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None
