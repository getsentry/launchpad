from typing import List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, StripBinaryFileInfo, StripBinaryInsightResult


class StripSymbolsInsight(Insight[StripBinaryInsightResult]):
    """Insight that analyzes debug sections in binaries and calculates potential savings."""

    # Debug sections that can be stripped to reduce binary size
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
        """Generate insights about debug sections that can be stripped from binaries.

        Args:
            input: Analysis input containing binary information

        Returns:
            Insight result with potential savings from stripping debug sections, or None if no savings
        """
        strip_files: List[StripBinaryFileInfo] = []
        total_savings = 0

        for binary_analysis in input.binary_analysis:
            # Skip non-MachO binaries (this is an Apple-specific insight)
            if not isinstance(binary_analysis, MachOBinaryAnalysis):
                continue

            # Calculate debug section sizes for this binary
            debug_section_size = 0

            for section_name, section_size in binary_analysis.sections.items():
                if section_name in self.DEBUG_SECTIONS:
                    debug_section_size += section_size

            # If this binary has debug sections, add it to the results
            if debug_section_size > 0:
                strip_file_info = StripBinaryFileInfo(
                    macho_binary=binary_analysis,
                    install_size_saved=debug_section_size,
                    download_size_saved=debug_section_size,  # Assuming 1:1 for debug sections
                )
                strip_files.append(strip_file_info)
                total_savings += debug_section_size

        # Return results only if we found debug sections to strip
        if strip_files:
            return StripBinaryInsightResult(
                files=strip_files,
                total_savings=total_savings,
            )

        return None
