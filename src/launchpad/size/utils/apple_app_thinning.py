"""iOS app thinning simulation for size analysis."""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapElement
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ThinningConfig:
    """Configuration for app thinning simulation."""

    target_image_scale: str = "2x"  # iPhone SE uses 2x scaling
    exclude_architectures: Set[str] = field(default_factory=set)
    exclude_platforms: Set[str] = field(default_factory=set)


class AppThinningSimulator:
    """Simulates iOS app thinning by filtering files based on device targets."""

    # Regex patterns for different thinning criteria
    IMAGE_SCALE_PATTERNS = {
        "1x": re.compile(r"@1x\.(png|jpg|jpeg|webp)$", re.IGNORECASE),
        "2x": re.compile(r"@2x\.(png|jpg|jpeg|webp)$", re.IGNORECASE),
        "3x": re.compile(r"@3x\.(png|jpg|jpeg|webp)$", re.IGNORECASE),
    }

    ARCHITECTURE_PATTERNS = {
        "arm64": re.compile(r"arm64", re.IGNORECASE),
        "armv7": re.compile(r"armv7", re.IGNORECASE),
        "x86_64": re.compile(r"x86_64", re.IGNORECASE),
        "i386": re.compile(r"i386", re.IGNORECASE),
    }

    PLATFORM_PATTERNS = {
        "iphone": re.compile(r"iphone", re.IGNORECASE),
        "ipad": re.compile(r"ipad", re.IGNORECASE),
        "universal": re.compile(r"universal", re.IGNORECASE),
    }

    def __init__(self, config: ThinningConfig) -> None:
        """Initialize the app thinning simulator.

        Args:
            config: Thinning configuration
        """
        self.config = config

    @classmethod
    def create_for_iphone_se(cls) -> AppThinningSimulator:
        """Create a thinning simulator configured for iPhone SE.

        Returns:
            Configured app thinning simulator for iPhone SE
        """
        config = ThinningConfig()
        # Exclude simulator architectures and iPad-specific files for iPhone SE
        config.exclude_architectures.update({"x86_64", "i386"})
        config.exclude_platforms.add("ipad")
        return cls(config)

    def apply_thinning(self, file_analysis: FileAnalysis) -> FileAnalysis:
        """Apply app thinning to the file analysis.

        Args:
            file_analysis: Original file analysis

        Returns:
            New file analysis with thinning applied
        """
        logger.info("Applying app thinning for iPhone SE (2x scaling)")

        # Filter out duplicates and recalculate parent sizes in one pass
        deduplicated_files = self._filter_duplicates(file_analysis.files)
        logger.info(f"Removed {len(file_analysis.files) - len(deduplicated_files)} duplicate files")

        filtered_files: List[FileInfo] = []
        total_original_size = 0
        total_filtered_size = 0

        for file_info in deduplicated_files:
            total_original_size += file_info.size

            if self._should_include_file(file_info):
                filtered_files.append(file_info)
                total_filtered_size += file_info.size

        logger.info(
            f"App thinning complete: {len(filtered_files)}/{len(file_analysis.files)} files included, "
            f"{total_filtered_size}/{total_original_size} bytes ({total_filtered_size / total_original_size * 100:.1f}%)"
        )

        return FileAnalysis(files=filtered_files)

    def _filter_duplicates(self, files: List[FileInfo]) -> List[FileInfo]:
        """Filter out duplicate image files based on filename and parent folder.

        Args:
            files: List of files to deduplicate

        Returns:
            List of files with duplicates removed and parent sizes recalculated
        """
        # Group files by their parent folder, filename, AND size (perfect duplicates only)
        file_groups: dict[tuple[str, str, int], List[FileInfo]] = {}

        for file_info in files:
            file_path = Path(file_info.path)
            parent_folder = str(file_path.parent)
            filename = file_path.name

            # Only deduplicate image files
            if file_path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
                key = (parent_folder, filename, file_info.size)
                if key not in file_groups:
                    file_groups[key] = []
                file_groups[key].append(file_info)
            else:
                # For non-image files, add them directly to avoid grouping issues
                key = (parent_folder, filename, file_info.size)
                if key not in file_groups:
                    file_groups[key] = []
                file_groups[key].append(file_info)

        # For each group, keep only one file (perfect duplicates)
        deduplicated_files: List[FileInfo] = []
        for (parent_folder, filename, size), file_list in file_groups.items():
            if len(file_list) == 1:
                # No duplicates, keep the file but process children
                file_info = file_list[0]
                if file_info.children:
                    file_info = self._deduplicate_children(file_info)
                deduplicated_files.append(file_info)
            else:
                # Perfect duplicates - keep only one, remove the rest
                kept_file = file_list[0]
                removed_files = file_list[1:]

                # Subtract removed file sizes from parent folder
                for removed_file in removed_files:
                    # Find the parent folder and reduce its size
                    for file_info in deduplicated_files:
                        if file_info.path == parent_folder:
                            file_info.size -= removed_file.size
                            break

                # Process children for the kept file
                if kept_file.children:
                    kept_file = self._deduplicate_children(kept_file)

                deduplicated_files.append(kept_file)
                logger.debug(
                    f"Removed {len(removed_files)} perfect duplicate(s) of {filename} (size: {size}) in {parent_folder}"
                )

        return deduplicated_files

    def _deduplicate_children(self, file_info: FileInfo) -> FileInfo:
        """Deduplicate children of a file (like asset catalog children).

        Args:
            file_info: File with children to deduplicate

        Returns:
            FileInfo with deduplicated children and updated size
        """
        if not file_info.children:
            return file_info

        # Group children by their path AND size (perfect duplicates only)
        child_groups: dict[tuple[str, int], List[TreemapElement]] = {}
        for child in file_info.children:
            key = (child.path or "", child.install_size)
            if key not in child_groups:
                child_groups[key] = []
            child_groups[key].append(child)

        # Keep only one child from each perfect duplicate group
        deduplicated_children: List[TreemapElement] = []
        original_children_size = sum(child.install_size for child in file_info.children)

        for (path, size), child_list in child_groups.items():
            if len(child_list) == 1:
                deduplicated_children.append(child_list[0])
            else:
                # Perfect duplicates - keep only one
                deduplicated_children.append(child_list[0])
                logger.debug(f"Removed {len(child_list) - 1} perfect duplicate child(ren) of {path} (size: {size})")

        # Calculate size reduction
        deduplicated_children_size = sum(child.install_size for child in deduplicated_children)
        removed_size = original_children_size - deduplicated_children_size

        if removed_size > 0:
            logger.debug(f"Reduced {file_info.path} size by {removed_size} bytes due to child deduplication")

        return FileInfo(
            full_path=file_info.full_path,
            path=file_info.path,
            size=file_info.size - removed_size,
            file_type=file_info.file_type,
            hash_md5=file_info.hash_md5,
            treemap_type=file_info.treemap_type,
            children=deduplicated_children,
        )

    def _should_include_file(self, file_info: FileInfo) -> bool:
        """Determine if a file should be included for the target device.

        Args:
            file_info: File information to evaluate

        Returns:
            True if the file should be included, False otherwise
        """
        file_path = Path(file_info.path)
        file_name = file_path.name.lower()

        # Check image scale exclusions
        if not self._should_include_image_scale(file_name):
            logger.debug(f"Excluding file due to image scale: {file_info.path}")
            return False

        # Check architecture exclusions
        if not self._should_include_architecture(file_name):
            logger.debug(f"Excluding file due to architecture: {file_info.path}")
            return False

        # Check platform exclusions
        if not self._should_include_platform(file_name):
            logger.debug(f"Excluding file due to platform: {file_info.path}")
            return False

        return True

    def _should_include_image_scale(self, file_name: str) -> bool:
        """Check if image file should be included based on scale."""
        # Check if this is an image file with scale suffix
        for scale, pattern in self.IMAGE_SCALE_PATTERNS.items():
            if pattern.search(file_name):
                # Only include if it matches our target scale
                return scale == self.config.target_image_scale

        # If no scale suffix, include it (base image)
        return True

    def _should_include_architecture(self, file_name: str) -> bool:
        """Check if file should be included based on architecture."""
        for arch, pattern in self.ARCHITECTURE_PATTERNS.items():
            if pattern.search(file_name):
                # Exclude if this architecture is in our exclusion list
                if arch in self.config.exclude_architectures:
                    return False

        return True

    def _should_include_platform(self, file_name: str) -> bool:
        """Check if file should be included based on platform."""
        for platform, pattern in self.PLATFORM_PATTERNS.items():
            if pattern.search(file_name):
                # Exclude if this platform is in our exclusion list
                if platform in self.config.exclude_platforms:
                    return False

        return True
