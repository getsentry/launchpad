from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import LocalizedStringInsightResult
from launchpad.size.models.common import FileInfo


class LocalizedStringsInsight(Insight[LocalizedStringInsightResult]):
    """Insight for analyzing localized strings files in iOS apps."""

    # 100KB threshold for reporting localized strings
    THRESHOLD_BYTES = 100 * 1024  # 100KB

    def generate(self, input: InsightsInput) -> LocalizedStringInsightResult | None:
        """Generate insight for localized strings files.

        Finds all Localizable.strings files in *.lproj directories,
        calculates total size, and returns insight if above threshold.
        """
        localized_files: list[FileInfo] = []
        total_size = 0

        # Find all Localizable.strings files in *.lproj directories
        for file_info in input.file_analysis.files:
            # Check if file path ends with *.lproj/Localizable.strings
            if file_info.path.endswith(".lproj/Localizable.strings"):
                localized_files.append(file_info)
                total_size += file_info.size

        # Only return insight if total size exceeds threshold
        if total_size > self.THRESHOLD_BYTES:
            return LocalizedStringInsightResult(
                files=localized_files,
                total_savings=total_size,
            )

        return None
