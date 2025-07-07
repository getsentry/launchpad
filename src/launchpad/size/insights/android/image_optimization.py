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

        for image_file, file_info in insights_input.image_map.items():
            if image_file.name.endswith("9.png"):
                continue

            original_size = get_file_size(image_file)
            with tempfile.NamedTemporaryFile(suffix=".webp", delete=True) as tmp_webp:
                try:
                    subprocess.run(
                        ["cwebp", "-quiet", "-lossless", str(image_file), "-o", tmp_webp.name],
                        capture_output=True,
                        check=True,
                    )
                except subprocess.CalledProcessError as e:
                    # If conversion fails, skip this image
                    logger.warning(f"Failed to convert {image_file} to WebP: {e}")
                    logger.debug(f"cwebp stderr: {e.stderr.decode()}")
                    continue

                webp_size = get_file_size(Path(tmp_webp.name))
                savings = original_size - webp_size
                if savings >= 500:
                    logger.debug(
                        f"Found optimizable image {image_file}: {original_size} -> {webp_size} bytes (savings: {savings})"
                    )
                    optimizeable_image_files.append(
                        OptimizeableImageFile(file_info=file_info, potential_savings=savings)
                    )
                else:
                    logger.debug(
                        f"Image {image_file} not worth optimizing: {original_size} -> {webp_size} bytes (savings: {savings} < 500)"
                    )

        return WebPOptimizationInsightResult(optimizeable_image_files=optimizeable_image_files)
