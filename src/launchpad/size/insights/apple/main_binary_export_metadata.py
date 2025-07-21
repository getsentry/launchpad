from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, MainBinaryExportMetadataResult


class MainBinaryExportMetadataInsight(Insight[MainBinaryExportMetadataResult]):
    """Insight for analyzing the exported symbols metadata in the main binary."""

    def generate(self, input: InsightsInput) -> MainBinaryExportMetadataResult | None:
        """Generate insight for main binary exported symbols analysis."""

        main_binary_analysis = None
        for analysis in input.binary_analysis:
            if isinstance(analysis, MachOBinaryAnalysis) and analysis.is_main_binary:
                main_binary_analysis = analysis
                break

        if not main_binary_analysis or not main_binary_analysis.binary_analysis:
            return None

        dyld_exports_trie_component = None
        for component in main_binary_analysis.binary_analysis.components:
            if component.name == "dyld_exports_trie":
                dyld_exports_trie_component = component
                break

        if not dyld_exports_trie_component:
            return None

        return MainBinaryExportMetadataResult(total_savings=dyld_exports_trie_component.size)
