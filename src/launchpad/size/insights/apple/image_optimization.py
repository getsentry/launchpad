from __future__ import annotations

import io
import logging

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pillow_heif  # type: ignore

from PIL import Image, ImageFile

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    ImageOptimizationInsightResult,
    OptimizableImageFile,
)
from launchpad.utils.logging import get_logger

pillow_heif.register_heif_opener()  # type: ignore
ImageFile.LOAD_TRUNCATED_IMAGES = True

# Silence noisy loggers
for noisy in ("PIL", "pillow_heif"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = get_logger(__name__)


@dataclass(slots=True)
class _OptimizationResult:
    savings: int
    optimized_size: int


class BaseImageOptimizationInsight(Insight[ImageOptimizationInsightResult], ABC):
    """Base class for image optimization insights with shared analysis logic."""

    OPTIMIZABLE_FORMATS = {"png", "jpg", "jpeg", "heif", "heic"}
    MIN_SAVINGS_THRESHOLD = 4096
    TARGET_JPEG_QUALITY = 85
    TARGET_HEIC_QUALITY = 85
    _MAX_WORKERS = 4

    @abstractmethod
    def _find_images(self, input: InsightsInput) -> List[FileInfo]:
        """Find and return list of images to analyze. Should include deduplication if needed."""
        pass

    def _preprocess_image(self, img: Image.Image, file_info: FileInfo) -> tuple[Image.Image, int, int]:
        """Preprocess image before optimization analysis.

        Args:
            img: The loaded PIL Image
            file_info: File metadata

        Returns:
            Tuple of (processed_image, baseline_size, baseline_savings):
            - processed_image: The image to analyze for optimization
            - baseline_size: Size of the processed image before optimization
            - baseline_savings: Savings from preprocessing alone (original - baseline)
        """
        return img, file_info.size, 0

    def generate(self, input: InsightsInput) -> ImageOptimizationInsightResult | None:  # noqa: D401
        files = self._find_images(input)
        if not files:
            return None

        results: List[OptimizableImageFile] = []
        with ThreadPoolExecutor(max_workers=min(self._MAX_WORKERS, len(files))) as executor:
            future_to_file = {executor.submit(self._analyze_image_optimization, f): f for f in files}
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    if result and result.potential_savings >= self.MIN_SAVINGS_THRESHOLD:
                        results.append(result)
                except Exception:  # pragma: no cover
                    logger.exception("Failed to analyze image in thread pool")

        if not results:
            return None

        results.sort(key=lambda x: x.potential_savings, reverse=True)
        total_savings = sum(f.potential_savings for f in results)

        return ImageOptimizationInsightResult(
            optimizable_files=results,
            total_savings=total_savings,
        )

    def _analyze_image_optimization(
        self,
        file_info: FileInfo,
    ) -> OptimizableImageFile | None:
        if file_info.full_path is None:
            logger.info("Skipping %s because it has no full path", file_info.path)
            return None

        try:
            with Image.open(file_info.full_path) as img:
                img.load()  # type: ignore

                processed_img, baseline_size, baseline_savings = self._preprocess_image(img, file_info)

                minify_savings = 0
                conversion_savings = 0
                minified_size: int | None = None
                heic_size: int | None = None

                fmt = (processed_img.format or file_info.file_type).lower()

                if fmt in {"png", "jpg", "jpeg"}:
                    if res := self._check_minification(processed_img, baseline_size, fmt):
                        minify_savings, minified_size = res.savings, res.optimized_size
                    if res := self._check_heic_conversion(processed_img, baseline_size):
                        conversion_savings, heic_size = res.savings, res.optimized_size
                elif fmt in {"heif", "heic"}:
                    if res := self._check_heic_minification(processed_img, baseline_size):
                        minify_savings, minified_size = res.savings, res.optimized_size

                total_minify = baseline_savings + minify_savings
                total_conversion = baseline_savings + conversion_savings

                if max(total_minify, total_conversion) < self.MIN_SAVINGS_THRESHOLD:
                    return None

                return OptimizableImageFile(
                    file_path=file_info.path,
                    current_size=file_info.size,
                    minify_savings=total_minify,
                    minified_size=minified_size,
                    conversion_savings=total_conversion,
                    heic_size=heic_size,
                )
        except Exception:
            logger.exception("Failed to open or process image file")
            return None

    def _check_minification(self, img: Image.Image, file_size: int, fmt: str) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                save_params = {"optimize": True}
                if fmt == "png":
                    img.save(buf, format="PNG", **save_params)
                else:
                    if img.mode in {"RGBA", "LA", "P"}:
                        with img.convert("RGB") as work:
                            work.save(buf, format="JPEG", quality=self.TARGET_JPEG_QUALITY, **save_params)
                    else:
                        img.save(buf, format="JPEG", quality=self.TARGET_JPEG_QUALITY, **save_params)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception:
            logger.exception("Image minification optimization failed")
            return None

    def _check_heic_conversion(self, img: Image.Image, file_size: int) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception:
            logger.exception("Image HEIC conversion optimization failed")
            return None

    def _check_heic_minification(self, img: Image.Image, file_size: int) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception:
            logger.exception("HEIC image minification failed")
            return None


class ImageOptimizationInsight(BaseImageOptimizationInsight):
    """Analyse image optimisation opportunities in iOS apps."""

    def _find_images(self, input: InsightsInput) -> List[FileInfo]:
        images: List[FileInfo] = []
        for fi in input.file_analysis.files:
            if fi.file_type == "car":
                images.extend(c for c in fi.children if self._is_optimizable_image_file(c))
            elif self._is_optimizable_image_file(fi):
                images.append(fi)
        return images

    def _is_optimizable_image_file(self, file_info: FileInfo) -> bool:
        if file_info.file_type.lower() not in self.OPTIMIZABLE_FORMATS:
            return False
        name = Path(file_info.path).name
        if name.startswith(("AppIcon", "iMessage App Icon")):
            return False
        return not any(part.endswith(".stickerpack") for part in file_info.path.split("/"))
