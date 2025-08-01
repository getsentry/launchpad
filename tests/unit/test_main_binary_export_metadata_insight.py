from pathlib import Path

from launchpad.size.insights.apple.main_binary_export_metadata import MainBinaryExportMetadataInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, SectionInfo, SegmentInfo
from launchpad.size.models.common import BaseAppInfo, FileAnalysis
from launchpad.size.models.insights import MainBinaryExportMetadataResult


class TestMainBinaryExportMetadataInsight:
    def setup_method(self):
        self.insight = MainBinaryExportMetadataInsight()

    def test_generate_with_main_binary_and_dyld_exports_trie(self):
        """Test that insight is generated when main binary has dyld_exports_trie section."""
        # Create a segment with the dyld_exports_trie section
        linkedit_segment = SegmentInfo(
            name="__LINKEDIT", sections=[SectionInfo(name="dyld_exports_trie", size=5000)], size=5000
        )

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[linkedit_segment],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 5000

    def test_generate_with_main_binary_without_dyld_exports_trie(self):
        """Test that no insight is generated when main binary lacks dyld_exports_trie section."""
        # Create segments without dyld_exports_trie
        text_segment = SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=50000)], size=50000)
        data_segment = SegmentInfo(name="__DATA", sections=[SectionInfo(name="__data", size=10000)], size=10000)

        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[text_segment, data_segment],  # No dyld_exports_trie
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
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
            segments=[],  # Empty for this test
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=False,  # Not a main binary
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_main_binary_but_empty_sections(self):
        """Test that no insight is generated when main binary has no sections."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],  # Empty for this test
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_empty_binary_analysis_list(self):
        """Test that no insight is generated when binary_analysis list is empty."""
        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
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
            segments=[
                SegmentInfo(name="__LINKEDIT", sections=[SectionInfo(name="dyld_exports_trie", size=8000)], size=8000)
            ],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
        )

        # Create framework binary (non-main)
        framework_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[],  # Empty for this test
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[framework_binary_analysis, main_binary_analysis],  # Framework first, main second
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, MainBinaryExportMetadataResult)
        assert result.total_savings == 8000

    def test_generate_with_dyld_exports_trie_zero_size(self):
        """Test that insight handles dyld_exports_trie section with zero size."""
        main_binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(
                    name="__LINKEDIT",
                    sections=[
                        SectionInfo(name="dyld_exports_trie", size=0)  # Zero size
                    ],
                    size=0,
                )
            ],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=True,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[main_binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None
