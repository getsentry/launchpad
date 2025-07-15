from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import LargeImageFileInsightResult


class LargeImageFileInsight(Insight[LargeImageFileInsightResult]):
    """Insight for identifying image files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeImageFileInsightResult:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB - chosen arbitrarily, we can change this later

        # Android supported image types: https://developer.android.com/media/platform/supported-formats#image-formats
        # Apple supported image types: https://developer.apple.com/library/archive/documentation/2DDrawing/Conceptual/DrawingPrintingiOS/LoadingImages/LoadingImages.html#//apple_ref/doc/uid/TP40010156-CH17-SW7
        image_types = [
            "png",
            "jpg",
            "jpeg",
            "webp",
            "bmp",
            "gif",
            "heif",
            "avif",
            "tif",
            "tiff",
            "ico",
            "heic",
            "cur",
            "xbm",
        ]
        image_files = [file for file in input.file_analysis.files if file.file_type in image_types]

        large_files = [file for file in image_files if file.size > size_threshold_bytes]

        # Sort by largest first
        large_files.sort(key=lambda f: f.size, reverse=True)

        # Calculate total potential savings (assuming files can be optimized to 50% of their size)
        total_savings = sum(file.size // 2 for file in large_files)

        return LargeImageFileInsightResult(files=large_files, total_savings=total_savings)
