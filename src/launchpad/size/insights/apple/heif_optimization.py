"""HEIF image optimization insight for Apple apps."""

import subprocess
import tempfile

from pathlib import Path
from typing import List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import HEIFOptimizationInsightResult, OptimizeableImageFile
from launchpad.utils.file_utils import get_file_size
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class HEIFOptimizationInsight(Insight[HEIFOptimizationInsightResult]):
    """Insight that identifies images that could be optimized by converting to HEIF format."""

    def generate(self, insights_input: InsightsInput) -> HEIFOptimizationInsightResult:
        """Generate HEIF optimization insights for the given input."""
        optimizeable_image_files: List[OptimizeableImageFile] = []

        for file_info in insights_input.file_analysis.files:
            if not self._is_optimizable_image(file_info):
                continue

            # Skip sticker packs as they don't support HEIF
            if ".stickerpack" in str(file_info.full_path):
                logger.debug(f"Skipping sticker pack image: {file_info.full_path}")
                continue

            original_size = get_file_size(Path(file_info.full_path))

            # Apply minimum size thresholds based on Swift implementation
            if not self._meets_size_threshold(file_info, original_size):
                continue

            savings = self._calculate_heif_savings(file_info, original_size)
            if savings and savings >= 4096:  # 4KB minimum savings like Swift
                logger.debug(
                    f"Found optimizable image {file_info.full_path}: {original_size} -> {original_size - savings} bytes (savings: {savings})"
                )
                optimizeable_image_files.append(OptimizeableImageFile(file_info=file_info, potential_savings=savings))
            else:
                logger.debug(f"Image {file_info.full_path} not worth optimizing: savings {savings} < 4KB")

        total_savings = sum(file.potential_savings for file in optimizeable_image_files)
        return HEIFOptimizationInsightResult(
            optimizeable_image_files=optimizeable_image_files, total_savings=total_savings
        )

    def _is_optimizable_image(self, file_info) -> bool:
        """Check if the file is an optimizable image format."""
        # Based on Swift implementation, we optimize PNG, JPG, JPEG, and HEIC files
        return file_info.file_type in ["png", "jpg", "jpeg", "heic"]

    def _meets_size_threshold(self, file_info, original_size: int) -> bool:
        """Check if the image meets the minimum size threshold for optimization."""
        # Based on Swift implementation:
        # - PNG: minimum 40KB
        # - JPG/JPEG/HEIC: minimum 10KB
        if file_info.file_type == "png":
            return original_size >= 40 * 1024  # 40KB
        else:
            return original_size >= 10 * 1024  # 10KB

    def _calculate_heif_savings(self, file_info, original_size: int) -> int | None:
        """Calculate potential savings by converting to HEIF format."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".heic", delete=True) as tmp_heic:
                # Use sips to convert to HEIF format
                # sips is the built-in macOS image processing tool
                subprocess.run(
                    [
                        "sips",
                        "-s",
                        "format",
                        "heic",
                        "-s",
                        "formatOptions",
                        "80",  # Quality setting
                        str(file_info.full_path),
                        "--out",
                        tmp_heic.name,
                    ],
                    capture_output=True,
                    check=True,
                    timeout=30,  # 30 second timeout
                )

                heif_size = get_file_size(Path(tmp_heic.name))
                savings = original_size - heif_size

                # Only return savings if the HEIF file is actually smaller
                if savings > 0:
                    return savings
                else:
                    logger.debug(f"HEIF conversion didn't save space for {file_info.full_path}")
                    return None

        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to convert {file_info.full_path} to HEIF: {e}")
            logger.debug(f"sips stderr: {e.stderr.decode() if e.stderr else 'No stderr'}")
            return None
        except subprocess.TimeoutExpired:
            logger.warning(f"HEIF conversion timed out for {file_info.full_path}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error converting {file_info.full_path} to HEIF: {e}")
            return None
