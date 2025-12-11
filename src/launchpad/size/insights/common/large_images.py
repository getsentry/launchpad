from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import FileSavingsResult, LargeImageFileInsightResult


class LargeImageFileInsight(Insight[LargeImageFileInsightResult]):
    """Insight for identifying image files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeImageFileInsightResult | None:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB - chosen arbitrarily, we can change this later

        # Android supported image types: https://developer.android.com/media/platform/supported-formats#image-formats
        # Apple supported image types: https://developer.apple.com/library/archive/documentation/2DDrawing/Conceptual/DrawingPrintingiOS/LoadingImages/LoadingImages.html#//apple_ref/doc/uid/TP40010156-CH17-SW7
        image_types = [
            "png",
            "pdf",
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

        # Recursively collect all files including nested children (e.g., images inside Assets.car)
        def flatten(item):
            yield item
            for child in item.children:
                yield from flatten(child)

        all_files = []
        for item in input.file_analysis.items:
            if not item.is_dir:
                all_files.extend(flatten(item))

        image_files = [f for f in all_files if f.file_type in image_types]

        large_files = [file for file in image_files if file.size > size_threshold_bytes]

        if len(large_files) == 0:
            return None

        large_files.sort(key=lambda f: f.size, reverse=True)

        file_savings = [
            FileSavingsResult(
                file_path=file.path,
                total_savings=file.size // 2,  # Assuming files can be optimized to 50% of their size
            )
            for file in large_files
        ]

        total_savings = sum(savings.total_savings for savings in file_savings)

        return LargeImageFileInsightResult(files=file_savings, total_savings=total_savings)
