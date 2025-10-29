from __future__ import annotations

import io

from typing import List

from PIL import Image

from launchpad.size.insights.apple.image_optimization import BaseImageOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import FileInfo
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class AlternateIconsOptimizationInsight(BaseImageOptimizationInsight):
    """Analyze alternate app icon optimization opportunities in iOS apps.

    Alternate app icons can be optimized without affecting the App Store listing since
    only the primary icon is displayed there. This insight identifies alternate icons
    that could be minified or converted to more efficient formats like HEIC.

    Icons are resized to device display size (180px for iPhone 3x) and back to store
    size (1024px) before optimization, since they only need quality for homescreen display.
    """

    IPHONE_3X_ICON_SIZE = 180  # Largest icon size displayed on device
    APP_STORE_ICON_SIZE = 1024  # Standard App Store icon size

    def _find_images(self, input: InsightsInput) -> List[FileInfo]:
        if not isinstance(input.app_info, AppleAppInfo):
            return []

        if not input.app_info.alternate_icon_names:
            return []

        alternate_icon_names = set(input.app_info.alternate_icon_names)
        car_files = [f for f in input.file_analysis.files if f.file_type == "car"]

        images: List[FileInfo] = []
        for car_file in car_files:
            if not car_file.children or (len(car_file.children) == 1 and car_file.children[0].path.endswith("/Other")):
                logger.warning(
                    "Asset catalog %s has no parsed children. ParsedAssets directory may be missing.", car_file.path
                )
                continue

            for child in car_file.children:
                if self._is_alternate_icon_file(child, alternate_icon_names):
                    images.append(child)

        return list({img.path: img for img in images}.values())

    def _preprocess_image(self, img: Image.Image, file_info: FileInfo) -> tuple[Image.Image, int, int]:
        resized = self._resize_icon_for_analysis(img)

        fmt = img.format or "PNG"
        with io.BytesIO() as buf:
            resized.save(buf, format=fmt)
            resized_size = buf.tell()

        baseline_savings = max(0, file_info.size - resized_size)
        return resized, resized_size, baseline_savings

    def _resize_icon_for_analysis(self, img: Image.Image) -> Image.Image:
        return img.resize((self.IPHONE_3X_ICON_SIZE, self.IPHONE_3X_ICON_SIZE), Image.Resampling.LANCZOS).resize(
            (self.APP_STORE_ICON_SIZE, self.APP_STORE_ICON_SIZE), Image.Resampling.LANCZOS
        )
