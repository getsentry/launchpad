from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import FileSavingsResult, MainBinaryExportMetadataResult


class MainBinaryExportMetadataInsight(Insight[MainBinaryExportMetadataResult]):
    """Insight for analyzing the exported symbols metadata in all main binaries."""

    MIN_EXPORTS_THRESHOLD = 1024

    def generate(self, input: InsightsInput) -> MainBinaryExportMetadataResult | None:
        """Generate insight for all main binary exported symbols analysis."""

        export_files: list[FileSavingsResult] = []

        # Analyze all main binaries (main app, app extensions, watch apps)
        for analysis in input.binary_analysis:
            # Look for dyld_exports_trie section in this main binary
            # Check in sections dict first
            if "dyld_exports_trie" in analysis.sections:
                export_size = analysis.sections["dyld_exports_trie"]
                if export_size >= self.MIN_EXPORTS_THRESHOLD:
                    export_files.append(
                        FileSavingsResult(
                            file_path=str(analysis.binary_relative_path),
                            total_savings=export_size,
                        )
                    )
            else:
                # Fallback: check in segments for any sections with this name
                for segment in analysis.segments:
                    for section in segment.sections:
                        if section.name == "dyld_exports_trie":
                            if section.size >= self.MIN_EXPORTS_THRESHOLD:
                                export_files.append(
                                    FileSavingsResult(
                                        file_path=str(analysis.binary_relative_path),
                                        total_savings=section.size,
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
