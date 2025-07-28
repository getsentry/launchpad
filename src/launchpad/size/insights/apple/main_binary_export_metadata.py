from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.insights import FileSavingsResult, MainBinaryExportMetadataResult


class MainBinaryExportMetadataInsight(Insight[MainBinaryExportMetadataResult]):
    """Insight for analyzing the exported symbols metadata in all main binaries."""

    MIN_EXPORTS_THRESHOLD = 1024

    def generate(self, input: InsightsInput) -> MainBinaryExportMetadataResult | None:
        """Generate insight for all main binary exported symbols analysis."""

        export_files: list[FileSavingsResult] = []

        # Analyze all main binaries (main app, app extensions, watch apps)
        for analysis in input.binary_analysis:
            if isinstance(analysis, MachOBinaryAnalysis) and analysis.is_main_binary:
                if not analysis.binary_analysis:
                    continue

                # Look for dyld_exports_trie component in this main binary
                for component in analysis.binary_analysis.components:
                    if component.name == "dyld_exports_trie":
                        if component.size >= self.MIN_EXPORTS_THRESHOLD:
                            export_files.append(
                                FileSavingsResult(
                                    file_path=analysis.binary_relative_path,
                                    total_savings=component.size,
                                )
                            )
                        break

        if not export_files:
            return None

        total_savings = sum(file.total_savings for file in export_files)

        return MainBinaryExportMetadataResult(
            total_savings=total_savings,
            files=export_files,
        )
