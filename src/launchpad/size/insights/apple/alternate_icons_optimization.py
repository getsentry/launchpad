from __future__ import annotations

import io

from pathlib import Path
from typing import Iterable, List

from PIL import Image

from launchpad.size.insights.apple.image_optimization import BaseImageOptimizationInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import OptimizableImageFile
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

    # Icon size constants matching Swift implementation
    IPHONE_3X_ICON_SIZE = 180  # Largest icon size displayed on device
    APP_STORE_ICON_SIZE = 1024  # Standard App Store icon size

    def _analyze_image_optimization(self, file_info: FileInfo) -> OptimizableImageFile | None:
        if file_info.full_path is None:
            logger.info("Skipping %s because it has no full path", file_info.path)
            return None

        try:
            with Image.open(file_info.full_path) as img:
                img.load()  # type: ignore

                resized = self._resize_icon_for_analysis(img)
                fmt = img.format or "PNG"
                with io.BytesIO() as buf:
                    resized.save(buf, format=fmt)
                    resized_size = buf.tell()

                return self._analyze_resized_icon(
                    resized, file_info.path, file_info.file_type, resized_size, file_info.size
                )
        except Exception as exc:
            logger.error("Failed to process %s: %s", file_info.path, exc)
            return None

    def _resize_icon_for_analysis(self, img: Image.Image) -> Image.Image:
        return img.resize((self.IPHONE_3X_ICON_SIZE, self.IPHONE_3X_ICON_SIZE), Image.Resampling.LANCZOS).resize(
            (self.APP_STORE_ICON_SIZE, self.APP_STORE_ICON_SIZE), Image.Resampling.LANCZOS
        )

    def _analyze_resized_icon(
        self,
        img: Image.Image,
        path: str,
        file_type: str,
        resized_size: int,
        original_file_size: int,
    ) -> OptimizableImageFile | None:
        minify_savings = 0
        conversion_savings = 0
        minified_size: int | None = None
        heic_size: int | None = None

        fmt = (img.format or file_type).lower()

        try:
            if fmt in {"png", "jpg", "jpeg"}:
                if res := self._check_minification(img, resized_size, fmt):
                    minify_savings, minified_size = res.savings, res.optimized_size
                if res := self._check_heic_conversion(img, resized_size):
                    conversion_savings, heic_size = res.savings, res.optimized_size
            elif fmt in {"heif", "heic"}:
                if res := self._check_heic_minification(img, resized_size):
                    minify_savings, minified_size = res.savings, res.optimized_size
        except Exception as exc:
            logger.error("Failed to analyze resized icon: %s", exc)
            return None

        resize_savings = max(0, original_file_size - resized_size)
        total_minify = resize_savings + minify_savings
        total_heic = resize_savings + conversion_savings

        if max(total_minify, total_heic) < self.MIN_SAVINGS_THRESHOLD:
            return None

        return OptimizableImageFile(
            file_path=path,
            current_size=original_file_size,
            minify_savings=total_minify,
            minified_size=minified_size,
            conversion_savings=total_heic,
            heic_size=heic_size,
        )

    def _iter_files_to_analyze(self, input: InsightsInput) -> Iterable[FileInfo]:
        if not isinstance(input.app_info, AppleAppInfo):
            return

        if not input.app_info.alternate_icon_names:
            return

        alternate_icon_names = set(input.app_info.alternate_icon_names)
        car_files = [f for f in input.file_analysis.files if f.file_type == "car"]

        for car_file in car_files:
            if not car_file.children or (len(car_file.children) == 1 and car_file.children[0].path.endswith("/Other")):
                logger.warning(
                    "Asset catalog %s has no parsed children. ParsedAssets directory may be missing.", car_file.path
                )
                continue

            for child in car_file.children:
                if self._is_alternate_icon_file(child, alternate_icon_names):
                    yield child

    def _deduplicate_results(self, results: List[OptimizableImageFile]) -> List[OptimizableImageFile]:
        return list({r.file_path: r for r in results}.values())

    def _is_alternate_icon_file(self, file_info: FileInfo, alternate_icon_names: set[str]) -> bool:
        return file_info.file_type.lower() in self.OPTIMIZABLE_FORMATS and any(
            Path(file_info.path).stem.startswith(name) for name in alternate_icon_names
        )
