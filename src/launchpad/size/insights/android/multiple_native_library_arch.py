from collections import defaultdict
from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    FileSavingsResult,
    MultipleNativeLibraryArchInsightResult,
)
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class MultipleNativeLibraryArchInsight(Insight[MultipleNativeLibraryArchInsightResult]):
    """Detect APKs that contain multiple native library architectures.

    Most users only need arm64-v8a libraries, but universal APKs often include
    x86, x86_64, and armeabi-v7a libraries that can be removed.
    """

    # Architectures that can most likely be removed (keeping only arm64-v8a)
    REMOVABLE_ARCHITECTURES = {"x86", "x86_64", "armeabi-v7a"}

    def generate(self, input: InsightsInput) -> MultipleNativeLibraryArchInsightResult | None:
        arch_to_files: dict[str, list[FileInfo]] = defaultdict(list)

        for file_info in input.file_analysis.files:
            if not file_info.path.endswith(".so"):
                continue

            # Extract architecture from path (lib/<arch>/*.so)
            path_parts = Path(file_info.path).parts
            if len(path_parts) >= 3 and path_parts[0] == "lib":
                arch = path_parts[1]
                arch_to_files[arch].append(file_info)
                logger.debug(f"Found native library {file_info.path} for architecture {arch}")

        # If we only have arm64-v8a or no native libraries, no optimization needed
        if len(arch_to_files) <= 1:
            return None

        # Shouldn't happen, but log in case
        if "arm64-v8a" not in arch_to_files:
            logger.warning("Found native libraries but no arm64-v8a architecture")
            return None

        removable_files: list[FileSavingsResult] = []
        total_savings = 0

        for arch, files in arch_to_files.items():
            if arch in self.REMOVABLE_ARCHITECTURES:
                for file_info in files:
                    removable_files.append(FileSavingsResult(file_path=file_info.path, total_savings=file_info.size))
                    total_savings += file_info.size
                    logger.debug(f"Removable {arch} library: {file_info.path} ({file_info.size} bytes)")

        if not removable_files:
            return None

        logger.info(
            f"Found {len(removable_files)} removable native libraries across {len([a for a in arch_to_files.keys() if a in self.REMOVABLE_ARCHITECTURES])} architectures, potential savings: {total_savings} bytes"
        )

        return MultipleNativeLibraryArchInsightResult(files=removable_files, total_savings=total_savings)
