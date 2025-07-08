import subprocess
import tempfile

from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.android import OptimizeableImageFile, WebPOptimizationInsightResult
from launchpad.utils.file_utils import get_file_size
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class WebPOptimizationInsight(Insight[WebPOptimizationInsightResult]):
    def generate(self, insights_input: InsightsInput) -> WebPOptimizationInsightResult:
        optimizeable_image_files: list[OptimizeableImageFile] = []

        for file_info in insights_input.file_analysis.files:
            if file_info.file_type not in ["png", "bmp", "jpg", "jpeg"]:
                continue

            if file_info.full_path.name.endswith(".9.png"):
                continue

            # TODO: verify that the file is actually an image

            original_size = get_file_size(Path(file_info.full_path))
            with tempfile.NamedTemporaryFile(suffix=".webp", delete=True) as tmp_webp:
                try:
                    subprocess.run(
                        ["cwebp", "-quiet", "-lossless", str(file_info.full_path), "-o", tmp_webp.name],
                        capture_output=True,
                        check=True,
                    )
                except subprocess.CalledProcessError as e:
                    # If conversion fails, skip this image
                    logger.warning(f"Failed to convert {file_info.full_path} to WebP: {e}")
                    logger.debug(f"cwebp stderr: {e.stderr.decode()}")
                    continue

                webp_size = get_file_size(Path(tmp_webp.name))
                savings = original_size - webp_size
                if savings >= 500:
                    logger.debug(
                        f"Found optimizable image {file_info.full_path}: {original_size} -> {webp_size} bytes (savings: {savings})"
                    )
                    optimizeable_image_files.append(
                        OptimizeableImageFile(file_info=file_info, potential_savings=savings)
                    )
                else:
                    logger.debug(
                        f"Image {file_info.full_path} not worth optimizing: {original_size} -> {webp_size} bytes (savings: {savings} < 500)"
                    )

        return WebPOptimizationInsightResult(optimizeable_image_files=optimizeable_image_files)
