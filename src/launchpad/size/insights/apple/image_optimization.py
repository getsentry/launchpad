"""Image optimization insight for Apple apps."""

from __future__ import annotations

import io
import logging

from dataclasses import dataclass
from pathlib import Path
from typing import List

import pillow_heif  # type: ignore

from PIL import Image

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import (
    ImageOptimizationInsightResult,
    OptimizableImageFile,
)
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapType
from launchpad.utils.logging import get_logger
from launchpad.utils.performance import trace

pillow_heif.register_heif_opener()  # type: ignore #
logging.getLogger("PIL").setLevel(logging.WARNING)  # silence Pillow debug
logging.getLogger("pillow_heif").setLevel(logging.WARNING)  # silence pillow‑heif debug

logger = get_logger(__name__)


@dataclass
class OptimizationResult:
    """Result of an image optimization check."""

    savings: int
    optimized_size: int


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

    # ------------------------------------------------------------------ #
    #  Public entry‑point
    # ------------------------------------------------------------------ #
    @trace("image_optimization.generate")
    def generate(self, input: InsightsInput) -> ImageOptimizationInsightResult | None:  # noqa: D401
        """Generate insight for image optimization opportunities."""
        optimizable_files: List[OptimizableImageFile] = []

        # Scan regular bundle files
        for file_info in filter(self._is_optimizable_image_file, input.file_analysis.files):
            try:
                optimizable_file = self._analyze_file_info(file_info)
                if optimizable_file and (
                    optimizable_file.minify_savings > 0 or optimizable_file.conversion_savings > 0
                ):
                    optimizable_files.append(optimizable_file)
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to analyze %s: %s", file_info.path, exc)

        for file_info in filter(lambda x: x.file_type == "car", input.file_analysis.files):
            for child in filter(self._is_optimizable_image_file, file_info.children):
                try:
                    optimizable_file = self._analyze_file_info(child)
                    if optimizable_file and (
                        optimizable_file.minify_savings > 0 or optimizable_file.conversion_savings > 0
                    ):
                        optimizable_files.append(optimizable_file)
                except Exception as exc:  # pragma: no cover
                    logger.error("Failed to analyze %s: %s", child.path, exc)

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
    #  Wrappers for different source objects
    # ------------------------------------------------------------------ #
    @trace("image_optimization.analyze_file_info")
    def _analyze_file_info(self, file_info: FileInfo) -> OptimizableImageFile | None:
        return self._analyze_image_optimization(
            full_path=file_info.full_path,
            file_size=file_info.size,
            file_type=file_info.file_type,
            display_path=file_info.path,
            source_object=file_info,
        )

    @trace("image_optimization.analyze_asset_element")
    def _analyze_asset_element(self, asset_element: str) -> OptimizableImageFile | None:
        """Analyse a single AssetCatalogElement extracted from an .xcassets archive."""
        # Detect the true file‑type from the asset's file name (fallback to png)
        file_type = Path(asset_element).suffix.lstrip(".").lower() or "png"

        mock_file_info = FileInfo(
            full_path=Path(asset_element),
            path=asset_element,
            size=1,
            file_type=file_type,
            hash_md5="",
            treemap_type=TreemapType.FILES,
            children=[],
        )

        return self._analyze_image_optimization(
            full_path=Path(asset_element),
            file_size=1,
            file_type=file_type,
            display_path=asset_element,
            source_object=mock_file_info,
        )

    # ------------------------------------------------------------------ #
    #  Core optimisation routine
    # ------------------------------------------------------------------ #
    @trace("image_optimization.analyze_single_image")
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
        minified_size = None
        conversion_savings = 0
        heic_size = None

        try:
            with Image.open(full_path) as img:
                img.load()  # type: ignore
                fmt = (img.format or file_type).lower()

                if fmt in {"png", "jpg", "jpeg"}:
                    # Check minification savings
                    minify_result = self._check_minification(img, file_size, fmt)
                    if minify_result:
                        minify_savings = minify_result.savings
                        minified_size = minify_result.optimized_size

                    # Check HEIC conversion savings
                    heic_result = self._check_heic_conversion(img, file_size)
                    if heic_result:
                        conversion_savings = heic_result.savings
                        heic_size = heic_result.optimized_size

                elif fmt in {"heif", "heic"}:
                    # For HEIC files, only check minification
                    heic_result = self._check_heic_minification(img, file_size)
                    if heic_result:
                        minify_savings = heic_result.savings
                        minified_size = heic_result.optimized_size

        except Exception as exc:  # pragma: no cover
            logger.error("Failed to process %s: %s", display_path, exc)

        # Only return if we have meaningful savings
        if minify_savings >= self.MIN_SAVINGS_THRESHOLD or conversion_savings >= self.MIN_SAVINGS_THRESHOLD:
            return OptimizableImageFile(
                file_info=source_object,
                current_size=file_size,
                minify_savings=minify_savings,
                minified_size=minified_size,
                conversion_savings=conversion_savings,
                heic_size=heic_size,
            )

        return None

    # ------------------------------------------------------------------ #
    #  Individual optimisation checks
    # ------------------------------------------------------------------ #
    @trace("image_optimization.check_minification")
    def _check_minification(
        self,
        img: Image.Image,
        file_size: int,
        format_name: str,
    ) -> OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                if format_name == "png":
                    img.save(buf, format="PNG", optimize=True)
                else:  # JPEG path
                    work = img
                    if work.mode in {"RGBA", "LA", "P"}:
                        work = work.convert("RGB")
                    work.save(buf, format="JPEG", quality=self.TARGET_JPEG_QUALITY, optimize=True)
                new_size = buf.tell()
            if new_size < file_size:
                return OptimizationResult(savings=file_size - new_size, optimized_size=new_size)
        except Exception as exc:  # pragma: no cover
            logger.error("Minification check failed: %s", exc)
        return None

    @trace("image_optimization.check_heic_conversion")
    def _check_heic_conversion(
        self,
        img: Image.Image,
        file_size: int,
    ) -> OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                work = img
                if work.mode in {"RGBA", "LA", "P"} and not (
                    work.mode == "RGBA" or (work.mode == "P" and "transparency" in work.info)
                ):
                    work = work.convert("RGB")
                work.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            if new_size < file_size:
                return OptimizationResult(savings=file_size - new_size, optimized_size=new_size)
        except Exception as exc:  # pragma: no cover
            logger.error("HEIC conversion check failed: %s", exc)
        return None

    @trace("image_optimization.check_heic_minification")
    def _check_heic_minification(
        self,
        img: Image.Image,
        file_size: int,
    ) -> OptimizationResult | None:
        try:
            with io.BytesIO() as buf:
                img.save(buf, format="HEIF", quality=self.TARGET_HEIC_QUALITY)
                new_size = buf.tell()
            if new_size < file_size:
                return OptimizationResult(savings=file_size - new_size, optimized_size=new_size)
        except Exception as exc:  # pragma: no cover
            logger.error("HEIC minification check failed: %s", exc)
        return None

    # ------------------------------------------------------------------ #
    #  Filtering helpers
    # ------------------------------------------------------------------ #
    def _is_optimizable_image_file(self, file_info: FileInfo) -> bool:
        if file_info.file_type.lower() not in self.OPTIMIZABLE_FORMATS:
            return False
        filename = Path(file_info.path).name
        if filename.startswith(("AppIcon", "iMessage App Icon")):
            return False
        if any(part.endswith(".stickerpack") for part in file_info.path.split("/")):
            return False
        return True
