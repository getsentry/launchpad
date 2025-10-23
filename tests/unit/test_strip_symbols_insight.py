from pathlib import Path

from launchpad.size.insights.apple.strip_symbols import StripSymbolsInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import (
    MachOBinaryAnalysis,
    SectionInfo,
    SegmentInfo,
    SymbolInfo,
)
from launchpad.size.models.common import BaseAppInfo, FileAnalysis
from launchpad.size.models.insights import StripBinaryInsightResult


class TestStripSymbolsInsight:
    def setup_method(self):
        self.insight = StripSymbolsInsight()

    def test_generate_with_debug_sections_and_symbols(self):
        """Test that insight is generated when binaries have both debug sections and strippable symbols."""
        symbol_info = SymbolInfo(
            symbol_sizes=[],
            swift_type_groups=[],
            objc_type_groups=[],
            cpp_type_groups=[],
            other_symbols=[],
            compiler_generated_symbols=[],
        )

        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            binary_relative_path=Path("Frameworks/MyFramework.framework/MyFramework"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=50000)], size=50000),
                SegmentInfo(
                    name="__DWARF",
                    sections=[SectionInfo(name="__debug_info", size=3000), SectionInfo(name="__debug_line", size=2000)],
                    size=5000,
                ),
                SegmentInfo(
                    name="__DATA",
                    sections=[SectionInfo(name="__data", size=10000), SectionInfo(name="__const", size=5000)],
                    size=15000,
                ),
            ],
            load_commands=[],
            symbol_info=symbol_info,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
            strippable_symbols_size=5000,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, StripBinaryInsightResult)
        assert len(result.files) == 1

        file_info = result.files[0]
        assert file_info.file_path == "Frameworks/MyFramework.framework/MyFramework"
        assert file_info.debug_sections_savings == 5000  # 3000 + 2000
        assert file_info.symbol_table_savings == 5000
        assert file_info.total_savings == 10000  # 5000 + 5000

        assert result.total_savings == 10000
        assert result.total_debug_sections_savings == 5000
        assert result.total_symbol_table_savings == 5000

    def test_generate_with_debug_sections_only(self):
        """Test that insight is generated when binaries have only debug sections."""
        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=30000)], size=30000),
                SegmentInfo(
                    name="__DWARF",
                    sections=[
                        SectionInfo(name="__debug_info", size=8000),
                        SectionInfo(name="__debug_abbrev", size=2000),
                        SectionInfo(name="__apple_names", size=1000),
                    ],
                    size=11000,
                ),
                SegmentInfo(name="__DATA", sections=[SectionInfo(name="__data", size=5000)], size=5000),
            ],
            load_commands=[],
            symbol_info=None,  # No symbol info
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, StripBinaryInsightResult)
        assert len(result.files) == 1

        file_info = result.files[0]
        assert file_info.file_path == "MyApp"
        assert file_info.debug_sections_savings == 11000  # 8000 + 2000 + 1000
        assert file_info.symbol_table_savings == 0
        assert file_info.total_savings == 11000

        assert result.total_savings == 11000
        assert result.total_debug_sections_savings == 11000
        assert result.total_symbol_table_savings == 0

    def test_generate_with_symbols_only(self):
        """Test that insight is generated when binaries have only strippable symbols."""
        symbol_info = SymbolInfo(
            symbol_sizes=[],
            swift_type_groups=[],
            objc_type_groups=[],
            cpp_type_groups=[],
            other_symbols=[],
            compiler_generated_symbols=[],
        )

        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=80000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=50000)], size=50000),
                SegmentInfo(
                    name="__DATA",
                    sections=[SectionInfo(name="__data", size=20000), SectionInfo(name="__const", size=10000)],
                    size=30000,
                ),
                # No debug sections
            ],
            load_commands=[],
            symbol_info=symbol_info,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
            strippable_symbols_size=15000,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, StripBinaryInsightResult)
        assert len(result.files) == 1

        file_info = result.files[0]
        assert file_info.file_path == "MyApp"
        assert file_info.debug_sections_savings == 0
        assert file_info.symbol_table_savings == 15000
        assert file_info.total_savings == 15000

        assert result.total_savings == 15000
        assert result.total_debug_sections_savings == 0
        assert result.total_symbol_table_savings == 15000

    def test_generate_with_multiple_binaries(self):
        """Test that insight correctly aggregates multiple binaries."""
        # Binary 1: Both debug sections and symbols
        symbol_info_1 = SymbolInfo(
            symbol_sizes=[],
            swift_type_groups=[],
            objc_type_groups=[],
            cpp_type_groups=[],
            other_symbols=[],
            compiler_generated_symbols=[],
        )

        binary_analysis_1 = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=50000)], size=50000),
                SegmentInfo(
                    name="__DWARF",
                    sections=[SectionInfo(name="__debug_info", size=2000), SectionInfo(name="__debug_line", size=1000)],
                    size=3000,
                ),
                SegmentInfo(name="__DATA", sections=[SectionInfo(name="__data", size=10000)], size=10000),
            ],
            load_commands=[],
            symbol_info=symbol_info_1,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
            strippable_symbols_size=3000,
        )

        # Binary 2: Only debug sections
        binary_analysis_2 = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/TestFramework.framework/TestFramework"),
            binary_relative_path=Path("Frameworks/TestFramework.framework/TestFramework"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=30000)], size=30000),
                SegmentInfo(
                    name="__DWARF",
                    sections=[SectionInfo(name="__debug_str", size=4000), SectionInfo(name="__apple_types", size=1500)],
                    size=5500,
                ),
                SegmentInfo(name="__DATA", sections=[SectionInfo(name="__data", size=5000)], size=5000),
            ],
            load_commands=[],
            symbol_info=None,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
        )

        # Binary 3: Only symbols
        symbol_info_3 = SymbolInfo(
            symbol_sizes=[],
            swift_type_groups=[],
            objc_type_groups=[],
            cpp_type_groups=[],
            other_symbols=[],
            compiler_generated_symbols=[],
        )

        binary_analysis_3 = MachOBinaryAnalysis(
            binary_absolute_path=Path("Frameworks/AnotherFramework.framework/AnotherFramework"),
            binary_relative_path=Path("Frameworks/AnotherFramework.framework/AnotherFramework"),
            executable_size=60000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=40000)], size=40000),
                SegmentInfo(name="__DATA", sections=[SectionInfo(name="__data", size=15000)], size=15000),
                # No debug sections
            ],
            load_commands=[],
            symbol_info=symbol_info_3,
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
            strippable_symbols_size=8000,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis_1, binary_analysis_2, binary_analysis_3],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, StripBinaryInsightResult)
        assert len(result.files) == 3

        assert result.files[0].total_savings >= result.files[1].total_savings
        assert result.files[1].total_savings >= result.files[2].total_savings

        expected_debug_savings = 3000 + 5500 + 0  # Binary 1: 3000, Binary 2: 5500, Binary 3: 0
        expected_symbol_savings = 3000 + 0 + 8000  # Binary 1: 3000, Binary 2: 0, Binary 3: 8000
        expected_total_savings = expected_debug_savings + expected_symbol_savings

        assert result.total_savings == expected_total_savings
        assert result.total_debug_sections_savings == expected_debug_savings
        assert result.total_symbol_table_savings == expected_symbol_savings

        app_file = next(f for f in result.files if f.file_path == "MyApp")
        assert app_file.debug_sections_savings == 3000
        assert app_file.symbol_table_savings == 3000
        assert app_file.total_savings == 6000

        test_framework_file = next(f for f in result.files if "TestFramework" in f.file_path)
        assert test_framework_file.debug_sections_savings == 5500
        assert test_framework_file.symbol_table_savings == 0
        assert test_framework_file.total_savings == 5500

        another_framework_file = next(f for f in result.files if "AnotherFramework" in f.file_path)
        assert another_framework_file.debug_sections_savings == 0
        assert another_framework_file.symbol_table_savings == 8000
        assert another_framework_file.total_savings == 8000

    def test_generate_with_no_strippable_content(self):
        """Test that no insight is generated when binaries have no strippable content."""
        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=30000)], size=30000),
                SegmentInfo(
                    name="__DATA",
                    sections=[SectionInfo(name="__data", size=15000), SectionInfo(name="__const", size=5000)],
                    size=20000,
                ),
                # No debug sections
            ],
            load_commands=[],
            symbol_info=None,  # No symbol info
            swift_metadata=None,
            is_main_binary=False,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_generate_with_zero_size_strippable_symbols(self):
        """Test that binaries with zero-size strippable symbols are ignored."""
        symbol_info = SymbolInfo(
            symbol_sizes=[],
            swift_type_groups=[],
            objc_type_groups=[],
            cpp_type_groups=[],
            other_symbols=[],
            compiler_generated_symbols=[],
        )

        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=50000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=30000)], size=30000),
                SegmentInfo(
                    name="__DATA",
                    sections=[SectionInfo(name="__data", size=15000), SectionInfo(name="__const", size=5000)],
                    size=20000,
                ),
                # No debug sections
            ],
            load_commands=[],
            symbol_info=symbol_info,
            swift_metadata=None,
            strippable_symbols_size=0,
            is_main_binary=False,
            header_size=32,
        )

        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert result is None

    def test_debug_sections_detection(self):
        """Test that all debug sections are correctly detected."""
        binary_analysis = MachOBinaryAnalysis(
            binary_absolute_path=Path("MyApp"),
            binary_relative_path=Path("MyApp"),
            executable_size=100000,
            architectures=["arm64"],
            linked_libraries=[],
            objc_method_names=[],
            segments=[
                SegmentInfo(name="__TEXT", sections=[SectionInfo(name="__text", size=50000)], size=50000),
                SegmentInfo(
                    name="__DWARF",
                    sections=[
                        SectionInfo(name="__debug_info", size=1000),
                        SectionInfo(name="__debug_abbrev", size=500),
                        SectionInfo(name="__debug_aranges", size=300),
                        SectionInfo(name="__debug_line", size=800),
                        SectionInfo(name="__debug_str", size=1200),
                        SectionInfo(name="__debug_loc", size=400),
                        SectionInfo(name="__debug_ranges", size=350),
                        SectionInfo(name="__debug_frame", size=600),
                        SectionInfo(name="__apple_names", size=700),
                        SectionInfo(name="__apple_types", size=450),
                        SectionInfo(name="__apple_namespac", size=250),
                        SectionInfo(name="__apple_objc", size=150),
                    ],
                    size=6700,
                ),
                SegmentInfo(
                    name="__DATA",
                    sections=[
                        SectionInfo(name="__data", size=10000),  # Non-debug section
                        SectionInfo(name="__const", size=5000),  # Non-debug section
                    ],
                    size=15000,
                ),
            ],
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
            binary_analysis=[binary_analysis],
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, StripBinaryInsightResult)
        assert len(result.files) == 1

        file_info = result.files[0]
        # Sum of all debug sections: 1000+500+300+800+1200+400+350+600+700+450+250+150 = 6700
        expected_debug_savings = 6700
        assert file_info.debug_sections_savings == expected_debug_savings
        assert file_info.symbol_table_savings == 0
        assert file_info.total_savings == expected_debug_savings

        # Test the new fields
        assert result.total_debug_sections_savings == expected_debug_savings
        assert result.total_symbol_table_savings == 0

    def test_generate_with_empty_binary_analysis(self):
        """Test that no insight is generated when binary_analysis is empty."""
        insights_input = InsightsInput(
            app_info=BaseAppInfo(name="TestApp", version="1.0", build="1", app_id="com.testapp"),
            file_analysis=FileAnalysis(files=[], directories=[]),
            treemap=None,
            binary_analysis=[],  # Empty list
        )

        result = self.insight.generate(insights_input)

        assert result is None
