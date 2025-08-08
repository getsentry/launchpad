import re

from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import LocalizedStringInsightResult


class LocalizedStringsInsight(Insight[LocalizedStringInsightResult]):
    """Insight for analyzing localized strings files in iOS apps. If the total size of the localized strings files is greater than the threshold, we recommend using our SmallStrings library."""

    THRESHOLD_BYTES = 100 * 1024  # 100KB

    ESTIMATED_SAVINGS_RATIO = 0.8  # Based on our user testing

    STRINGS_FILE_DENYLIST = ["LaunchScreen.strings"]

    # Pattern to match .strings files directly inside .lproj directories
    # Matches: en.lproj/Localizable.strings, Base.lproj/InfoPlist.strings
    _LPROJ_STRINGS_PATTERN = re.compile(r"[^/]+\.lproj/[^/]+\.strings$")

    def generate(self, input: InsightsInput) -> LocalizedStringInsightResult | None:
        """Generate insight for localized strings files.

        Finds all Localizable.strings files in *.lproj directories,
        calculates total size, and returns insight if above threshold.
        """
        localized_files: list[FileInfo] = []
        total_size = 0

        # Find all .strings files in *.lproj directories
        for file_info in input.file_analysis.files:
            if self._LPROJ_STRINGS_PATTERN.search(file_info.path):
                filename = Path(file_info.path).name
                if filename not in self.STRINGS_FILE_DENYLIST:
                    localized_files.append(file_info)
                    total_size += file_info.size

        estimated_savings = int(total_size * self.ESTIMATED_SAVINGS_RATIO)
        if estimated_savings > self.THRESHOLD_BYTES:
            return LocalizedStringInsightResult(
                total_savings=estimated_savings,
            )

        return None
