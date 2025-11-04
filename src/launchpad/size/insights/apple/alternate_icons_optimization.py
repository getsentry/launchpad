from __future__ import annotations

import io

from typing import List

from PIL import Image

from launchpad.size.insights.apple.image_optimization import BaseImageOptimizationInsight, _OptimizationResult
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

    When HEIC images are used as app icons in asset catalogs, iOS stores them as two
    separate images - a small compressed HEIC and an significantly larger additional variant.
    Resizing via our suggested bash script seems to end up with a sum of the two being
    approximately 1.5x larger than the size of a resized HEIC using PIL. The size of the HEIC
    image depends on a number of things (variety of colors, complexity of the image, etc) that
    has proven hard to reliably predict, so we use a rough multiplier to account for the difference.
    """

    IPHONE_3X_ICON_SIZE = 180  # Largest icon size displayed on device
    APP_STORE_ICON_SIZE = 1024  # Standard App Store icon size
    HEIC_TOTAL_SIZE_MULTIPLIER = (
        1.5  # Multiplier for total HEIC size (accounts for PIL encoding differences + iOS variants)
    )

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

    def _resize_icon_for_analysis(self, img: Image.Image) -> Image.Image:
        return img.resize((self.IPHONE_3X_ICON_SIZE, self.IPHONE_3X_ICON_SIZE), Image.Resampling.LANCZOS).resize(
            (self.APP_STORE_ICON_SIZE, self.APP_STORE_ICON_SIZE), Image.Resampling.LANCZOS
        )

    def _check_minification(self, img: Image.Image, file_size: int, fmt: str) -> _OptimizationResult | None:
        # Skip minification for alternate icons - only suggest HEIC conversion
        return None

    def _check_heic_conversion(
        self, img: Image.Image, file_size: int, file_path: str = ""
    ) -> _OptimizationResult | None:
        try:
            resized_small = img.resize((self.IPHONE_3X_ICON_SIZE, self.IPHONE_3X_ICON_SIZE), Image.Resampling.LANCZOS)
            resized_large = resized_small.resize(
                (self.APP_STORE_ICON_SIZE, self.APP_STORE_ICON_SIZE), Image.Resampling.LANCZOS
            )

            with io.BytesIO() as buf:
                resized_large.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                small_heic_size = buf.tell()

            total_heic_size = int(small_heic_size * self.HEIC_TOTAL_SIZE_MULTIPLIER)
            potential_savings = file_size - total_heic_size

            if total_heic_size < file_size:
                return _OptimizationResult(potential_savings, total_heic_size)
            else:
                return None
        except Exception:
            logger.exception("Image HEIC conversion optimization failed for %s", file_path or "unknown")
            return None
