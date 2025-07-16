import re

from collections import defaultdict

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import LooseImageGroup, LooseImagesInsightResult
from launchpad.size.models.common import FileInfo
from launchpad.utils.file_utils import to_nearest_block_size


class LooseImagesInsight(Insight[LooseImagesInsightResult]):
    """Insight for analyzing raw images that are not included in iOS asset catalogs."""

    IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "webp", "heif", "heic", "tiff", "tif", "bmp"}

    # Pattern to extract canonical image name (removes @2x, @3x, ~ipad, etc.)
    CANONICAL_NAME_PATTERN = re.compile(r"^(.+?)(?:[@~][^.]*)?(\.[^.]+)$")

    def generate(self, input: InsightsInput) -> LooseImagesInsightResult | None:
        """Generate insight for raw images analysis.

        Finds all image files that are not in asset catalogs,
        excludes system images like AppIcon and iMessage App Icon,
        groups them by canonical name, and calculates potential savings.
        """

        # Find all image files that are not in asset catalogs
        raw_image_files: list[FileInfo] = []
        for file_info in input.file_analysis.files:
            if self._is_raw_image_file(file_info):
                raw_image_files.append(file_info)

        if not raw_image_files:
            return None

        # Group images by canonical name
        image_groups_dict: dict[str, list[FileInfo]] = defaultdict(list)
        for image_file in raw_image_files:
            canonical_name = self._get_canonical_image_name(image_file.path)
            image_groups_dict[canonical_name].append(image_file)

        image_groups = [
            LooseImageGroup(canonical_name=canonical_name, images=images)
            for canonical_name, images in image_groups_dict.items()
        ]

        image_groups.sort(key=lambda group: group.total_size, reverse=True)

        # Calculate total savings avoiding double-counting:
        # 1. Files eliminated via app thinning: full block-aligned disk usage saved
        # 2. Files that remain: only block alignment waste saved

        total_savings = 0
        eliminated_files: set[str] = set()

        # First pass: identify files that would be eliminated via app thinning
        for group in image_groups:
            eliminated_files.update(self._get_eliminated_files(group))

        # Second pass: calculate savings for each file
        for image_file in raw_image_files:
            block_aligned_size = to_nearest_block_size(image_file.size, APPLE_FILESYSTEM_BLOCK_SIZE)

            if image_file.path in eliminated_files:
                # File eliminated via app thinning: save full block-aligned size
                total_savings += block_aligned_size
            else:
                # File remains: save only block alignment waste
                total_savings += block_aligned_size - image_file.size

        return LooseImagesInsightResult(
            image_groups=image_groups,
            total_file_count=len(raw_image_files),
            total_savings=total_savings,
        )

    def _is_raw_image_file(self, file_info: FileInfo) -> bool:
        """Check if a file is a raw image that should be moved to an asset catalog."""
        # Must be an image file
        if file_info.file_type not in self.IMAGE_EXTENSIONS:
            return False

        # Skip if it's already in an asset catalog (.car file)
        if ".car/" in file_info.path:
            return False

        # Skip system icons
        filename = file_info.path.split("/")[-1]  # Get just the filename
        if filename.startswith("AppIcon") or filename.startswith("iMessage App Icon"):
            return False

        # Only consider top-level images or images in immediate subdirectories
        # (not deeply nested, as those are likely already organized)
        path_parts = file_info.path.split("/")
        if len(path_parts) > 3:  # Allow up to 2 levels deep: folder/subfolder/image.png
            return False

        # Skip .stickerpack directories (as mentioned in Swift code)
        if any(part.endswith(".stickerpack") for part in path_parts):
            return False

        return True

    def _get_canonical_image_name(self, file_path: str) -> str:
        """Extract canonical image name by removing resolution suffixes like @2x, @3x, ~ipad."""
        filename = file_path.split("/")[-1]  # Get just the filename

        match = self.CANONICAL_NAME_PATTERN.match(filename)
        if match:
            base_name = match.group(1)
            extension = match.group(2)
            return base_name + extension

        return filename  # Fallback to original filename if pattern doesn't match

    def _get_eliminated_files(self, group: LooseImageGroup) -> list[str]:
        """Get list of file paths that would be eliminated via app thinning for @3x devices."""
        # Only apply app thinning to groups that have scale indicators
        has_scale_indicators = any("@" in img.path for img in group.images)
        if not has_scale_indicators:
            return []

        # First pass: determine what scales are available
        has_3x = False
        has_2x = False

        for image in group.images:
            filename = image.path.split("/")[-1]
            if "@3x" in filename:
                has_3x = True
            elif "@2x" in filename:
                has_2x = True

        # Second pass: identify files to eliminate
        eliminated: list[str] = []
        for image in group.images:
            filename = image.path.split("/")[-1]

            if "@3x" in filename:
                # Keep @3x for target device
                continue
            elif "@2x" in filename:
                # Eliminate @2x if we have @3x
                if has_3x:
                    eliminated.append(image.path)
            elif "@1x" in filename or not any(scale in filename for scale in ["@2x", "@3x"]):
                # Eliminate @1x if we have higher resolution variants
                if has_3x or has_2x:
                    eliminated.append(image.path)

        return eliminated
