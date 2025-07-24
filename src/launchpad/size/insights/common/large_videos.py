from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import FileSavingsResult, LargeVideoFileInsightResult


class LargeVideoFileInsight(Insight[LargeVideoFileInsightResult]):
    """Insight for identifying video files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeVideoFileInsightResult | None:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB

        # Android supported video types: https://developer.android.com/media/platform/supported-formats#video-formats
        # Apple supported video types: https://stackoverflow.com/questions/1535836/video-file-formats-supported-in-iphone
        video_types = ["mp4", "3gp", "webm", "mkv", "mov", "m4v"]
        video_files = [file for file in input.file_analysis.files if file.file_type in video_types]

        large_files = [file for file in video_files if file.size > size_threshold_bytes]

        if len(large_files) == 0:
            return None

        large_files.sort(key=lambda f: f.size, reverse=True)

        file_savings = [FileSavingsResult(file_path=file.path, total_savings=file.size // 2) for file in large_files]

        total_savings = sum(savings.total_savings for savings in file_savings)

        return LargeVideoFileInsightResult(files=file_savings, total_savings=total_savings)
