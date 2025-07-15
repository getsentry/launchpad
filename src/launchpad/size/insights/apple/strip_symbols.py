from typing import List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, StripBinaryFileInfo, StripBinaryInsightResult


class StripSymbolsInsight(Insight[StripBinaryInsightResult]):
    """Insight that analyzes debug sections and debugging symbols in binaries and calculates potential savings."""

    DEBUG_SECTIONS = {
        "__debug_info",
        "__debug_abbrev",
        "__debug_aranges",
        "__debug_line",
        "__debug_str",
        "__debug_loc",
        "__debug_ranges",
        "__debug_frame",
        "__apple_names",
        "__apple_types",
        "__apple_namespac",
        "__apple_objc",
    }

    def generate(self, input: InsightsInput) -> StripBinaryInsightResult | None:
        """Generate insights about debug sections and symbols that can be stripped from binaries."""
        strip_files: List[StripBinaryFileInfo] = []
        total_savings = 0
        total_debug_sections_savings = 0
        total_symbol_table_savings = 0

        for binary_analysis in input.binary_analysis:
            if not isinstance(binary_analysis, MachOBinaryAnalysis):
                continue

            debug_section_size = 0
            for section_name, section_size in binary_analysis.sections.items():
                if section_name in self.DEBUG_SECTIONS:
                    debug_section_size += section_size

            symbol_savings = 0
            if binary_analysis.symbol_info:
                symbol_savings = binary_analysis.symbol_info.strippable_symbols_size

            strippable_size = debug_section_size + symbol_savings
            if strippable_size > 0:
                strip_file_info = StripBinaryFileInfo(
                    file_path=str(binary_analysis.binary_path),
                    debug_sections_savings=debug_section_size,
                    symbol_table_savings=symbol_savings,
                    total_savings=strippable_size,
                )
                strip_files.append(strip_file_info)
                total_savings += strippable_size
                total_debug_sections_savings += debug_section_size
                total_symbol_table_savings += symbol_savings

        strip_files.sort(key=lambda x: x.total_savings, reverse=True)

        if strip_files:
            return StripBinaryInsightResult(
                files=strip_files,
                total_savings=total_savings,
            )

        return None
