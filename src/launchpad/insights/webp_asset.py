"""WebP asset optimization insights for Android apps."""

from __future__ import annotations

import tempfile

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.common import FileInfo
from ..models.insights import WebpAssetInsightResult
from ..utils.image.cwebp import Cwebp
from ..utils.logging import get_logger
from .common import Insight, InsightsInput

logger = get_logger(__name__)

SUPPORTED_IMAGE_FORMATS = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp"}

MIN_IMAGE_SIZE = 4 * 1024

MIN_SAVINGS_THRESHOLD = 500


class WebpAssetInsight(Insight[WebpAssetInsightResult]):
    def generate(self, input: InsightsInput) -> WebpAssetInsightResult:
        """Generate WebP optimization insights from analysis results.

        Args:
            input: Analysis input containing file information

        Returns:
            WebpAssetInsightResult with optimization opportunities
        """
        # Store artifact reference for use in helper methods
        self._current_artifact = input.artifact

        optimization_opportunities: List[Dict[str, Any]] = []
        total_potential_savings = 0

        try:
            cwebp = Cwebp()
        except FileNotFoundError:
            logger.warning("cwebp not found, skipping WebP optimization analysis")
            return WebpAssetInsightResult(
                optimization_opportunities=[],
                total_potential_savings=0,
                total_savings=0,
            )

        # Find image files that could be optimized
        for file_info in input.file_analysis.files:
            if not self._is_optimizable_image(file_info):
                continue

            try:
                savings = self._analyze_image_optimization(file_info, cwebp)
                if savings and savings["potential_savings"] >= MIN_SAVINGS_THRESHOLD:
                    optimization_opportunities.append(savings)
                    total_potential_savings += savings["potential_savings"]
            except Exception as e:
                logger.debug(f"Failed to analyze image {file_info.path}: {e}")
                continue

        optimization_opportunities.sort(key=lambda x: x["potential_savings"], reverse=True)

        return WebpAssetInsightResult(
            optimization_opportunities=optimization_opportunities,
            total_potential_savings=total_potential_savings,
            total_savings=total_potential_savings,
        )

    def _is_optimizable_image(self, file_info: FileInfo) -> bool:
        """Check if a file is an optimizable image.

        Args:
            file_info: File information

        Returns:
            True if the file can be optimized with WebP
        """
        file_path = Path(file_info.path.lower())
        if file_path.suffix not in SUPPORTED_IMAGE_FORMATS:
            return False

        if file_path.suffix == ".webp":
            return False

        if file_path.name.endswith(".9.png"):
            return False

        if file_info.size < MIN_IMAGE_SIZE:
            return False

        path_str = file_info.path.lower()
        if not any(
            directory in path_str
            for directory in [
                "res/",
                "assets/",
            ]
        ):
            return False

        return True

    def _analyze_image_optimization(self, file_info: FileInfo, cwebp: Cwebp) -> Optional[Dict[str, Any]]:
        """Analyze a single image for WebP optimization potential.

        Args:
            file_info: File information for the image
            cwebp: Cwebp instance for compression

        Returns:
            Dictionary with optimization details or None if no optimization possible
        """
        original_size = file_info.size
        file_path = Path(file_info.path)
        file_extension = file_path.suffix.lower()

        try:
            with tempfile.NamedTemporaryFile(suffix=file_extension, delete=False) as temp_input:
                temp_input_path = Path(temp_input.name)

            with tempfile.NamedTemporaryFile(suffix=".webp", delete=False) as temp_output:
                temp_output_path = Path(temp_output.name)

            try:
                if not self._extract_image_from_artifact(file_info, temp_input_path):
                    logger.debug(f"Failed to extract image {file_info.path} from APK")
                    return None

                webp_size = self._compress_image_with_cwebp(temp_input_path, temp_output_path, cwebp)

                if webp_size is None:
                    logger.debug(f"Failed to compress image {file_info.path} with cwebp")
                    return None

                potential_savings = original_size - webp_size

                # Only suggest optimization if savings are significant
                if potential_savings >= MIN_SAVINGS_THRESHOLD:
                    return {
                        "file_path": file_info.path,
                        "original_size": original_size,
                        "webp_size": webp_size,
                        "potential_savings": potential_savings,
                        "compression_ratio": webp_size / original_size,
                        "file_type": file_extension,
                    }

                return None

            finally:
                # Clean up temporary files
                try:
                    temp_input_path.unlink(missing_ok=True)
                    temp_output_path.unlink(missing_ok=True)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error analyzing image {file_info.path}: {e}")
            return None

    def _extract_image_from_artifact(self, file_info: FileInfo, temp_input_path: Path) -> bool:
        """Extract an image file from the artifact to a temporary location.

        Args:
            file_info: File information for the image
            temp_input_path: Path to write the extracted image

        Returns:
            True if extraction was successful, False otherwise
        """
        try:
            # Get the artifact from the insights input
            if not hasattr(self, "_current_artifact") or self._current_artifact is None:
                logger.debug("No artifact available for file extraction")
                return False

            from ..artifacts.android.aab import AAB
            from ..artifacts.android.apk import APK
            from ..artifacts.android.zipped_aab import ZippedAAB
            from ..artifacts.android.zipped_apk import ZippedAPK

            artifacts = []
            if isinstance(self._current_artifact, AAB):
                artifacts = self._current_artifact.get_primary_apks()
            elif isinstance(self._current_artifact, ZippedAAB):
                artifacts = self._current_artifact.get_primary_apks()
            elif isinstance(self._current_artifact, ZippedAPK):
                artifacts.append(self._current_artifact.get_primary_apk())
            elif isinstance(self._current_artifact, APK):
                artifacts.append(self._current_artifact)
            else:
                logger.debug(f"Unsupported artifact type: {type(self._current_artifact)}")
                return False

            for artifact in artifacts:
                extract_path = artifact.get_extract_path()
                image_path = extract_path / file_info.path

                if image_path.exists() and image_path.is_file():
                    # Copy the file to the temporary location
                    import shutil

                    shutil.copy2(image_path, temp_input_path)
                    return True

            logger.debug(f"Image file {file_info.path} not found in any APK")
            return False

        except Exception as e:
            logger.debug(f"Error extracting image {file_info.path}: {e}")
            return False

    def _compress_image_with_cwebp(self, temp_input_path: Path, temp_output_path: Path, cwebp: Cwebp) -> Optional[int]:
        """Compress an image using cwebp and return the compressed size.

        Args:
            temp_input_path: Path to the input image
            temp_output_path: Path to write the compressed WebP image
            cwebp: Cwebp instance

        Returns:
            Compressed file size in bytes, or None if compression failed
        """
        try:
            args = []

            args.append("-lossless")

            args.extend([str(temp_input_path), "-o", str(temp_output_path)])

            cwebp.run(args)

            if temp_output_path.exists():
                return temp_output_path.stat().st_size
            else:
                logger.debug("cwebp did not create output file")
                return None

        except Exception as e:
            logger.debug(f"Error compressing image with cwebp: {e}")
            return None
