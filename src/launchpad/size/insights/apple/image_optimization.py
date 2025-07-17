"""Image optimization insight for Apple apps."""

from __future__ import annotations

import io
import logging
from typing import List

from PIL import Image                     # ← real import used at runtime
import pillow_heif                        # HEIF/HEIC plugin for Pillow

pillow_heif.register_heif_opener()        # ← make Pillow recognise HEIF/HEIC
logging.getLogger("PIL").setLevel(logging.WARNING)          # or INFO
logging.getLogger("pillow_heif").setLevel(logging.WARNING)  # optional

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import (
    ImageOptimizationInsightResult,
    OptimizableImageFile,
)
from launchpad.size.models.common import FileInfo
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ImageOptimizationInsight(Insight[ImageOptimizationInsightResult]):
    """Insight for analyzing image optimization opportunities in iOS apps."""

    # Supported image formats for optimization
    OPTIMIZABLE_FORMATS = {"png", "jpg", "jpeg", "heif", "heic"}

    # Minimum savings threshold to report (500 bytes)
    MIN_SAVINGS_THRESHOLD = 500

    # Target quality for JPEG optimization
    TARGET_JPEG_QUALITY = 85

    # Target quality for HEIC conversion / minification
    TARGET_HEIC_QUALITY = 85

    # --------------------------------------------------------------------- #
    #  Public entry-point
    # --------------------------------------------------------------------- #
    def generate(self, input: InsightsInput) -> ImageOptimizationInsightResult | None:
        """Generate insight for image optimization opportunities."""
        optimizable_files: List[OptimizableImageFile] = []

        # Filter image files that can be optimized
        image_files = [
            f for f in input.file_analysis.files if self._is_optimizable_image(f)
        ]

        for file_info in image_files:
            try:
                optimizations = self._analyze_image_optimization(file_info)
                optimizable_files.extend(optimizations)
            except Exception as exc:
                logger.error(f"Failed to analyze {file_info.path}: {exc}")

        if not optimizable_files:
            return None

        optimizable_files.sort(key=lambda x: x.potential_savings, reverse=True)
        total_savings = sum(f.potential_savings for f in optimizable_files)

        return ImageOptimizationInsightResult(
            optimizable_files=optimizable_files,
            total_file_count=len(optimizable_files),
            total_savings=total_savings,
        )

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _is_optimizable_image(self, file_info: FileInfo) -> bool:
        """Return True if the file is a candidate for optimization."""
        if file_info.file_type.lower() not in self.OPTIMIZABLE_FORMATS:
            return False

        filename = file_info.path.split("/")[-1]
        if filename.startswith(("AppIcon", "iMessage App Icon")):
            return False

        if any(part.endswith(".stickerpack") for part in file_info.path.split("/")):
            return False

        return file_info.size >= 1024  # skip tiny images (<1 KB)

    # ------------------------------------------------------------------ #
    def _analyze_image_optimization(self, file_info: FileInfo) -> List[OptimizableImageFile]:
        """Return a list of savings opportunities for one image (may be empty)."""
        results: List[OptimizableImageFile] = []

        try:
            with open(file_info.full_path, "rb") as fh:
                img = Image.open(io.BytesIO(fh.read()))
                img.load()  # make sure it’s fully read before re-saving

            fmt = (img.format or file_info.file_type).lower()

            if fmt in {"png", "jpg", "jpeg"}:
                results.extend(filter(None, [
                    self._check_minification(img, file_info, fmt),
                    self._check_heic_conversion(img, file_info),
                ]))
            elif fmt in {"heif", "heic"}:
                minified = self._check_heic_minification(img, file_info)
                if minified:
                    results.append(minified)

        except Exception as exc:
            logger.error(f"Failed to process {file_info.path}: {exc}")

        # Only keep worthwhile suggestions
        return [r for r in results if r.potential_savings >= self.MIN_SAVINGS_THRESHOLD]

    # ------------------------------------------------------------------ #
    #  Individual checks
    # ------------------------------------------------------------------ #
    def _check_minification(
        self,
        img: Image.Image,
        file_info: FileInfo,
        format_name: str,
    ) -> OptimizableImageFile | None:
        """Try losslessly compressing PNG or re-compressing JPEG to 85 % quality."""
        try:
            with io.BytesIO() as buf:
                if format_name == "png":
                    img.save(buf, format="PNG", optimize=True)
                else:  # JPEG
                    if img.mode in {"RGBA", "LA", "P"}:
                        img = img.convert("RGB")
                    img.save(buf, format="JPEG", quality=self.TARGET_JPEG_QUALITY, optimize=True)

                new_size = buf.tell()
            if new_size < file_info.size:
                return OptimizableImageFile(
                    file_info=file_info,
                    optimization_type="minify",
                    current_size=file_info.size,
                    optimized_size=new_size,
                    current_quality=None,
                )
        except Exception as exc:
            logger.error(f"Minification check failed for {file_info.path}: {exc}")

        return None

    def _check_heic_conversion(
        self,
        img: Image.Image,
        file_info: FileInfo,
    ) -> OptimizableImageFile | None:
        """Convert PNG/JPEG → HEIC and report savings, if any."""
        try:
            with io.BytesIO() as buf:
                save_target = img
                if img.mode in {"RGBA", "LA", "P"} and not (
                    img.mode == "RGBA"
                    or (img.mode == "P" and "transparency" in img.info)
                ):
                    save_target = img.convert("RGB")

                save_target.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()

            if new_size < file_info.size:
                return OptimizableImageFile(
                    file_info=file_info,
                    optimization_type="convert_to_heic",
                    current_size=file_info.size,
                    optimized_size=new_size,
                )
        except Exception as exc:
            logger.error(f"HEIC conversion check failed for {file_info.path}: {exc}")

        return None

    def _check_heic_minification(
        self,
        img: Image.Image,
        file_info: FileInfo,
    ) -> OptimizableImageFile | None:
        """Re-compress HEIC at 85 % quality and report savings."""
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY, optimize=True)
                new_size = buf.tell()

            if new_size < file_info.size:
                return OptimizableImageFile(
                    file_info=file_info,
                    optimization_type="minify_heic",
                    current_size=file_info.size,
                    optimized_size=new_size,
                )
        except Exception as exc:
            logger.error(f"HEIC minification check failed for {file_info.path}: {exc}")

        return None
