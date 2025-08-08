import re

from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import LocalizedStringInsightResult


class LocalizedStringsInsight(Insight[LocalizedStringInsightResult]):
    """Insight for analyzing localized strings files in iOS apps. If the total size of the localized strings files is greater than the threshold, we recommend using our SmallStrings library."""

    SAVINGS_THRESHOLD_BYTES = 100 * 1024  # 100KB

    STRINGS_FILE_DENYLIST = ["LaunchScreen.strings"]

    # Pattern to match .strings files directly inside .lproj directories
    # Matches: en.lproj/Localizable.strings, Base.lproj/InfoPlist.strings
    _LPROJ_STRINGS_PATTERN = re.compile(r"[^/]+\.lproj/[^/]+\.strings$")

    def generate(self, input: InsightsInput) -> LocalizedStringInsightResult | None:
        """Generate insight for localized strings files.

        Finds all Localizable.strings files in *.lproj directories,
        calculates total size, and returns insight if above threshold.
        """
        total_size = 0

        # Find all .strings files in *.lproj directories
        for file_info in input.file_analysis.files:
            if self._LPROJ_STRINGS_PATTERN.search(file_info.path):
                filename = Path(file_info.path).name
                if filename not in self.STRINGS_FILE_DENYLIST:
                    total_size += file_info.size

        small_strings_savings = int(total_size * 0.5)
        if small_strings_savings > self.SAVINGS_THRESHOLD_BYTES:
            return LocalizedStringInsightResult(
                total_savings=small_strings_savings,
            )

        return None
