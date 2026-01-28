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
            if not analysis.is_main_binary:
                continue

            if not analysis.architecture_slices:
                continue

            # Sum export trie size across all architecture slices
            export_trie_size = sum(
                arch_slice.linkedit_info.export_trie_size
                for arch_slice in analysis.architecture_slices
                if arch_slice.linkedit_info
            )

            if export_trie_size >= self.MIN_EXPORTS_THRESHOLD:
                export_files.append(
                    FileSavingsResult(
                        file_path=str(analysis.binary_relative_path),
                        total_savings=export_trie_size,
                    )
                )

        if not export_files:
            return None

        export_files.sort(key=lambda x: x.total_savings, reverse=True)

        return MainBinaryExportMetadataResult(
            total_savings=sum(file.total_savings for file in export_files),
            files=export_files,
        )
