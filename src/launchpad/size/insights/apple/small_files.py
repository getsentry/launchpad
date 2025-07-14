from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import SmallFilesInsightResult
from launchpad.size.models.common import FileInfo


class SmallFilesInsight(Insight[SmallFilesInsightResult]):
    """Insight for analyzing small files that waste space due to filesystem block size constraints."""

    # Only report if there are more than 100 total files in the app
    TOTAL_FILES_THRESHOLD = 100

    def generate(self, input: InsightsInput) -> SmallFilesInsightResult | None:
        """Generate insight for small files analysis.

        Finds all files smaller than APPLE_FILESYSTEM_BLOCK_SIZE (4096 bytes),
        and calculates potential savings if they were combined into an asset catalog.
        Only returns an insight if the app has more than 100 total files.
        """
        small_files: list[FileInfo] = []
        total_savings = 0

        for file_info in input.file_analysis.files:
            if file_info.size < APPLE_FILESYSTEM_BLOCK_SIZE:
                small_files.append(file_info)
                # Calculate wasted space due to block size alignment
                wasted_space = APPLE_FILESYSTEM_BLOCK_SIZE - file_info.size
                total_savings += wasted_space

        if len(input.file_analysis.files) > self.TOTAL_FILES_THRESHOLD:
            return SmallFilesInsightResult(
                files=small_files,
                file_count=len(small_files),
                total_savings=total_savings,
            )

        return None
