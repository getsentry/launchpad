from __future__ import annotations

import io
import logging

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

import pillow_heif  # type: ignore

from PIL import Image

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import (
    ImageOptimizationInsightResult,
    OptimizableImageFile,
)
from launchpad.size.models.common import FileInfo
from launchpad.utils.logging import get_logger

pillow_heif.register_heif_opener()  # type: ignore

# Silence noisy loggers
for noisy in ("PIL", "pillow_heif"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = get_logger(__name__)


@dataclass(slots=True)
class _OptimizationResult:
    savings: int
    optimized_size: int


class ImageOptimizationInsight(Insight[ImageOptimizationInsightResult]):
    """Analyse image optimisation opportunities in iOS apps."""

    OPTIMIZABLE_FORMATS = {"png", "jpg", "jpeg", "heif", "heic"}
    MIN_SAVINGS_THRESHOLD = 4096
    TARGET_JPEG_QUALITY = 85
    TARGET_HEIC_QUALITY = 85
    _MAX_WORKERS = 8

    def generate(self, input: InsightsInput) -> ImageOptimizationInsightResult | None:  # noqa: D401
        files = list(self._iter_optimizable_files(input.file_analysis.files))
        if not files:
            return None

        results: List[OptimizableImageFile] = []
        with ThreadPoolExecutor(max_workers=min(self._MAX_WORKERS, len(files))) as executor:
            future_to_file = {executor.submit(self._analyze_file_info, f): f for f in files}
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    if result and result.potential_savings >= self.MIN_SAVINGS_THRESHOLD:
                        results.append(result)
                except Exception as exc:  # pragma: no cover
                    file_info = future_to_file[future]
                    logger.error("Failed to analyse %s: %s", file_info.path, exc)

        if not results:
            return None

        results.sort(key=lambda x: x.potential_savings, reverse=True)
        total_savings = sum(f.potential_savings for f in results)

        return ImageOptimizationInsightResult(
            optimizable_files=results,
            total_savings=total_savings,
        )

    def _analyze_file_info(self, file_info: FileInfo) -> OptimizableImageFile | None:
        return self._analyze_image_optimization(
            full_path=file_info.full_path,
            file_size=file_info.size,
            file_type=file_info.file_type,
            display_path=file_info.path,
            source_object=file_info,
        )

    def _analyze_image_optimization(
        self,
        *,
        full_path: Path,
        file_size: int,
        file_type: str,
        display_path: str,
        source_object: FileInfo,
    ) -> OptimizableImageFile | None:
        minify_savings = 0
        conversion_savings = 0
        minified_size: int | None = None
        heic_size: int | None = None

        try:
            with Image.open(full_path) as img:
                img.load()  # type: ignore
                fmt = (img.format or file_type).lower()

                if fmt in {"png", "jpg", "jpeg"}:
                    if res := self._check_minification(img, file_size, fmt):
                        minify_savings, minified_size = res.savings, res.optimized_size
                    if res := self._check_heic_conversion(img, file_size):
                        conversion_savings, heic_size = res.savings, res.optimized_size
                elif fmt in {"heif", "heic"}:
                    if res := self._check_heic_minification(img, file_size):
                        minify_savings, minified_size = res.savings, res.optimized_size
        except Exception as exc:
            logger.error("Failed to process %s: %s", display_path, exc)
            return None

        if max(minify_savings, conversion_savings) < self.MIN_SAVINGS_THRESHOLD:
            return None

        return OptimizableImageFile(
            file_info=source_object,
            current_size=file_size,
            minify_savings=minify_savings,
            minified_size=minified_size,
            conversion_savings=conversion_savings,
            heic_size=heic_size,
        )

    def _check_minification(self, img: Image.Image, file_size: int, fmt: str) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                save_params = {"optimize": True}
                if fmt == "png":
                    img.save(buf, format="PNG", **save_params)
                else:
                    work = img.convert("RGB") if img.mode in {"RGBA", "LA", "P"} else img
                    work.save(buf, format="JPEG", quality=self.TARGET_JPEG_QUALITY, **save_params)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception as exc:
            logger.error("Minification check failed: %s", exc)
            return None

    def _check_heic_conversion(self, img: Image.Image, file_size: int) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception as exc:
            logger.error("HEIC conversion check failed: %s", exc)
            return None

    def _check_heic_minification(self, img: Image.Image, file_size: int) -> _OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            return _OptimizationResult(file_size - new_size, new_size) if new_size < file_size else None
        except Exception as exc:
            logger.error("HEIC minification check failed: %s", exc)
            return None

    def _iter_optimizable_files(self, files: Sequence[FileInfo]) -> Iterable[FileInfo]:
        for fi in files:
            if fi.file_type == "car":
                yield from (c for c in fi.children if self._is_optimizable_image_file(c))
            elif self._is_optimizable_image_file(fi):
                yield fi

    def _is_optimizable_image_file(self, file_info: FileInfo) -> bool:
        if file_info.file_type.lower() not in self.OPTIMIZABLE_FORMATS:
            return False
        name = Path(file_info.path).name
        if name.startswith(("AppIcon", "iMessage App Icon")):
            return False
        return not any(part.endswith(".stickerpack") for part in file_info.path.split("/"))
