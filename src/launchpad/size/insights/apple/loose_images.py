import os
import re

from collections import defaultdict

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import FileSavingsResult, FileSavingsResultGroup, LooseImagesInsightResult


class LooseImagesInsight(Insight[LooseImagesInsightResult]):
    """Insight for analyzing loose images that can benefit from app thinning via asset catalogs."""

    IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "webp", "heif", "heic", "tiff", "tif", "bmp"}

    # Pattern to extract canonical image name (removes @2x, @3x, ~ipad, etc.)
    CANONICAL_NAME_PATTERN = re.compile(r"^(.+?)(?:[@~][^.]*)?(\.[^.]+)$")

    def generate(self, input: InsightsInput) -> LooseImagesInsightResult | None:
        """Generate insight for loose images that can benefit from app thinning.

        Only includes image groups with multiple scale variants (e.g., @1x, @2x, @3x)
        since these are the ones that can benefit from being moved to asset catalogs.
        """

        # Find all image files that are not in asset catalogs
        raw_image_files: list[FileInfo] = []
        for file_info in input.file_analysis.files:
            if self._is_loose_image_file(file_info):
                raw_image_files.append(file_info)

        if not raw_image_files:
            return None

        # Group images by canonical name
        image_groups_dict: dict[str, list[FileSavingsResult]] = defaultdict(list)
        for image_file in raw_image_files:
            canonical_name = self._get_canonical_image_name(image_file.path)
            savings_result = FileSavingsResult(file_path=image_file.path, total_savings=image_file.size)
            image_groups_dict[canonical_name].append(savings_result)

        # Only include groups with multiple images (multiple scale variants)
        # Single images can't benefit from app thinning
        multi_scale_groups: list[FileSavingsResultGroup] = []
        for canonical_name, images in image_groups_dict.items():
            if len(images) > 1:
                # Calculate total savings: sum of savings from all images minus the largest one
                # (since the largest image would be kept for the highest resolution)
                max_size = max(img.total_savings for img in images)
                group_total_savings = sum(img.total_savings for img in images) - max_size

                multi_scale_groups.append(
                    FileSavingsResultGroup(
                        name=canonical_name,
                        files=images,
                        total_savings=group_total_savings,
                    )
                )

        if not multi_scale_groups:
            return None

        multi_scale_groups.sort(key=lambda group: group.total_savings, reverse=True)

        # Calculate total savings: sum of savings from all groups
        total_savings = sum(group.total_savings for group in multi_scale_groups)

        return LooseImagesInsightResult(
            groups=multi_scale_groups,
            total_savings=total_savings,
        )

    def _is_loose_image_file(self, file_info: FileInfo) -> bool:
        """Check if a file is a loose image that should be moved to an asset catalog."""
        # Must be an image file
        if file_info.file_type not in self.IMAGE_EXTENSIONS:
            return False

        # Skip system icons
        filename = os.path.basename(file_info.path)
        if filename.startswith("AppIcon") or filename.startswith("iMessage App Icon"):
            return False

        # Skip .stickerpack directories (as mentioned in Swift code)
        path_parts = file_info.path.split("/")
        if any(part.endswith(".stickerpack") for part in path_parts):
            return False

        return True

    def _get_canonical_image_name(self, file_path: str) -> str:
        """Extract canonical image name by removing resolution suffixes like @2x, @3x, ~ipad."""
        filename = os.path.basename(file_path)

        match = self.CANONICAL_NAME_PATTERN.match(filename)
        if match:
            base_name = match.group(1)
            extension = match.group(2)
            return base_name + extension

        return filename  # Fallback to original filename if pattern doesn't match

    def _get_eliminated_files(self, group: FileSavingsResultGroup) -> list[str]:
        """Get list of file paths that would be eliminated via app thinning for @3x devices."""
        # Only apply app thinning to groups that have scale indicators
        has_scale_indicators = any("@" in img.file_path for img in group.files)
        if not has_scale_indicators:
            return []

        # First pass: determine what scales are available
        has_3x = False
        has_2x = False

        for image in group.files:
            filename = os.path.basename(image.file_path)
            if "@3x" in filename:
                has_3x = True
            elif "@2x" in filename:
                has_2x = True

        # Second pass: identify files to eliminate
        eliminated: list[str] = []
        for image in group.files:
            filename = os.path.basename(image.file_path)

            if "@3x" in filename:
                # Keep @3x for target device
                continue
            elif "@2x" in filename:
                # Eliminate @2x if we have @3x
                if has_3x:
                    eliminated.append(image.file_path)
            elif "@1x" in filename or not any(scale in filename for scale in ["@2x", "@3x"]):
                # Eliminate @1x if we have higher resolution variants
                if has_3x or has_2x:
                    eliminated.append(image.file_path)

        return eliminated
