from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import (
    LargeVideoFileInsightResult,
)


class LargeVideoFileInsight(Insight[LargeVideoFileInsightResult]):
    """Insight for identifying video files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeVideoFileInsightResult:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB

        # Android supported video types: https://developer.android.com/media/platform/supported-formats#video-formats
        # Apple supported video types: https://stackoverflow.com/questions/1535836/video-file-formats-supported-in-iphone
        video_types = ["mp4", "3gp", "webm", "mkv", "mov", "m4v"]
        video_files = [file for file in input.file_analysis.files if file.file_type in video_types]

        large_files = [file for file in video_files if file.size > size_threshold_bytes]

        # Sort by largest first
        large_files.sort(key=lambda f: f.size, reverse=True)

        # Calculate total potential savings (assuming files can be optimized to 50% of their size)
        total_savings = sum(file.size // 2 for file in large_files)

        return LargeVideoFileInsightResult(files=large_files, total_savings=total_savings)
