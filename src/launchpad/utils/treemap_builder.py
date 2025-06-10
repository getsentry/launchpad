"""Treemap builder for creating hierarchical size analysis from file data."""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from ..models.common import FileAnalysis, FileInfo
from ..models.treemap import TreemapElement, TreemapResults, TreemapType
from ..utils.logging import get_logger

logger = get_logger(__name__)

# Platform-specific page sizes
PLATFORM_PAGE_SIZES = {
    "ios": 16 * 1024,  # 16KB for modern iOS devices
    "android": 4 * 1024,  # 4KB for Android devices
    "unknown": 4 * 1024,  # Default to 4KB
}


class TreemapBuilder:
    """Builder for creating treemap structures from file analysis data."""

    def __init__(self, app_name: str = "App", platform: str = "unknown", page_size: Optional[int] = None) -> None:
        """Initialize the treemap builder.

        Args:
            app_name: Name of the root app element
            platform: Platform name (ios, android, etc.)
            page_size: Override page size for alignment, or None to use platform default
        """
        self.app_name = app_name
        self.platform = platform
        default_page_size = PLATFORM_PAGE_SIZES.get(platform, PLATFORM_PAGE_SIZES["unknown"])
        self.page_size = page_size or default_page_size

    def build_file_treemap(self, file_analysis: FileAnalysis) -> TreemapResults:
        """Build a treemap from file analysis results.

        Args:
            file_analysis: File analysis results containing all files

        Returns:
            Complete treemap results with hierarchical structure
        """
        logger.info(f"Building file-based treemap for {self.platform} platform")

        # Log the impact of page alignment
        self._log_alignment_impact(file_analysis)

        # Build hierarchical structure from file paths
        children = self._build_file_hierarchy(file_analysis)

        # Create root treemap element
        root = TreemapElement(
            name=self.app_name,
            install_size=0,  # Will be calculated from children
            download_size=0,  # Will be calculated from children
            element_type=None,
            path=None,
            children=children,
        )

        # Calculate category breakdown
        category_breakdown = self._calculate_category_breakdown(file_analysis)

        return TreemapResults(
            root=root,
            total_install_size=root.total_install_size,
            total_download_size=root.total_download_size,
            file_count=file_analysis.file_count,
            category_breakdown=category_breakdown,
            platform=self.platform,
        )

    def _calculate_aligned_install_size(self, file_size: int) -> int:
        """Calculate the actual install size considering platform page alignment.

        Args:
            file_size: Actual file content size in bytes

        Returns:
            Install size rounded up to nearest page boundary
        """
        if file_size == 0:
            return 0

        # Round up to nearest page boundary
        # Formula: ((size - 1) // page_size + 1) * page_size
        return ((file_size - 1) // self.page_size + 1) * self.page_size

    def _build_file_hierarchy(self, file_analysis: FileAnalysis) -> List[TreemapElement]:
        """Build hierarchical file structure from file analysis.

        Args:
            file_analysis: File analysis results

        Returns:
            List of root-level TreemapElement objects
        """
        # Collect all files
        all_files: List[FileInfo] = []
        for files_by_type in file_analysis.files_by_type.values():
            all_files.extend(files_by_type)

        # Group files by their directory structure
        directory_map: Dict[str, List[FileInfo]] = defaultdict(list)
        root_files: List[FileInfo] = []

        for file_info in all_files:
            path_obj = Path(file_info.path)
            if len(path_obj.parts) == 1:
                # Root level file
                root_files.append(file_info)
            else:
                # File in subdirectory - group by first directory
                first_dir = path_obj.parts[0]
                directory_map[first_dir].append(file_info)

        # Create TreemapElement objects
        elements: List[TreemapElement] = []

        # Add root level files
        for file_info in root_files:
            element = self._create_file_element(file_info, file_info.path)
            elements.append(element)

        # Add directories with their contents
        for dir_name, files in directory_map.items():
            dir_element = self._create_directory_element(dir_name, files)
            elements.append(dir_element)

        return elements

    def _create_file_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        """Create a TreemapElement for a single file.

        Args:
            file_info: File information
            display_name: Display name for the element

        Returns:
            TreemapElement for the file
        """
        # Calculate platform-aligned install size and compressed download size
        install_size = self._calculate_aligned_install_size(file_info.size)
        download_size = self._estimate_download_size(file_info)

        # Build context-appropriate details
        details: Dict[str, object] = {
            "actualSize": file_info.size,  # Store the actual file size
            "alignedSize": install_size,  # Store the aligned size
            "hash": file_info.hash_md5,  # File hash for deduplication
        }

        # Add file extension only for actual files (not binary subsections)
        if file_info.file_type and file_info.file_type != "unknown":
            details["fileExtension"] = file_info.file_type

        return TreemapElement(
            name=display_name,
            install_size=install_size,
            download_size=download_size,
            element_type=self._get_file_category(file_info),
            path=file_info.path,
            details=details,
        )

    def _create_directory_element(self, dir_name: str, files: List[FileInfo]) -> TreemapElement:
        """Create a TreemapElement for a directory containing files.

        Args:
            dir_name: Directory name
            files: Files in the directory

        Returns:
            TreemapElement for the directory
        """
        # Group files by subdirectory within this directory
        subdirs: Dict[str, List[FileInfo]] = defaultdict(list)
        direct_files: List[FileInfo] = []

        for file_info in files:
            path_obj = Path(file_info.path)

            # Find the relative path from current directory
            relative_parts: List[str] = []
            found_current_dir = False

            for i, part in enumerate(path_obj.parts):
                if part == dir_name and not found_current_dir:
                    # Found our current directory, get the parts after it
                    relative_parts = list(path_obj.parts[i + 1 :])
                    found_current_dir = True
                    break

            # If we didn't find the current directory in the path, check if this file
            # is at the root level where the directory name is the first part
            if not found_current_dir:
                if len(path_obj.parts) > 0 and path_obj.parts[0] == dir_name:
                    relative_parts = list(path_obj.parts[1:])
                else:
                    # This file doesn't belong in this directory, skip it
                    continue

            if len(relative_parts) == 0:
                # This shouldn't happen, but handle it gracefully
                continue
            elif len(relative_parts) == 1:
                # Direct file in this directory
                direct_files.append(file_info)
            else:
                # File in subdirectory
                subdir = relative_parts[0]
                subdirs[subdir].append(file_info)

        # Create child elements
        children: List[TreemapElement] = []

        # Add direct files
        for file_info in direct_files:
            filename = os.path.basename(file_info.path)
            element = self._create_file_element(file_info, filename)
            children.append(element)

        # Add subdirectories recursively
        for subdir_name, subdir_files in subdirs.items():
            subdir_element = self._create_directory_element(subdir_name, subdir_files)
            children.append(subdir_element)

        return TreemapElement(
            name=dir_name,
            install_size=0,  # Directory itself has no size
            download_size=0,  # Directory itself has no size
            element_type=self._get_directory_type(dir_name),
            path=None,  # Directories don't have file paths
            children=children,
        )

    def _estimate_download_size(self, file_info: FileInfo) -> int:
        """Estimate download size (compressed) for a file.

        Args:
            file_info: File information

        Returns:
            Estimated download size in bytes
        """
        # Compression ratios by file type (rough estimates)
        compression_ratios = {
            # Already compressed formats
            "png": 1.0,
            "jpg": 1.0,
            "jpeg": 1.0,
            "gif": 1.0,
            "zip": 1.0,
            "gz": 1.0,
            # Text-based files (compress well)
            "plist": 0.3,
            "xml": 0.3,
            "json": 0.3,
            "txt": 0.4,
            "strings": 0.4,
            # Binary files (moderate compression)
            "dylib": 0.7,
            "framework": 0.7,
            "": 0.8,  # Executable files (no extension)
            # Other files
            "nib": 0.6,
            "storyboard": 0.4,
            "car": 0.9,  # Asset catalogs are already optimized
        }

        ratio = compression_ratios.get(file_info.file_type.lower(), 0.6)  # Default 60% of original
        return int(file_info.size * ratio)

    def _get_file_category(self, file_info: FileInfo) -> TreemapType:
        """Determine treemap type for a file.

        Args:
            file_info: File information

        Returns:
            Appropriate TreemapType
        """
        file_type = file_info.file_type.lower()

        # Executable files (no extension typically)
        if file_type == "" and "/" not in file_info.path and "." not in os.path.basename(file_info.path):
            return TreemapType.EXECUTABLES

        # Framework files
        if ".framework" in file_info.path:
            return TreemapType.FRAMEWORKS

        # Plist files
        if file_type == "plist":
            return TreemapType.PLISTS

        # Asset files
        if file_type in ["png", "jpg", "jpeg", "gif", "pdf", "car"]:
            return TreemapType.ASSETS

        # Resource files
        if file_type in ["nib", "storyboard", "strings", "lproj"]:
            return TreemapType.RESOURCES

        return TreemapType.FILES

    def _get_directory_type(self, directory_name: str) -> Optional[TreemapType]:
        """Determine treemap type for a directory.

        Args:
            directory_name: Name of the directory

        Returns:
            Appropriate TreemapType or None
        """
        name_lower = directory_name.lower()

        if ".framework" in name_lower:
            return TreemapType.FRAMEWORKS
        elif name_lower in ["assets", "images"]:
            return TreemapType.ASSETS
        elif ".lproj" in name_lower:
            return TreemapType.RESOURCES

        return None  # Generic directory

    def _calculate_category_breakdown(self, file_analysis: FileAnalysis) -> Dict[str, Dict[str, int]]:
        """Calculate size breakdown by category.

        Args:
            file_analysis: File analysis results

        Returns:
            Category breakdown with install and download sizes
        """
        breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"install": 0, "download": 0})

        for file_type, files in file_analysis.files_by_type.items():
            for file_info in files:
                treemap_type = self._get_file_category(file_info)
                category = treemap_type.value

                # Use iOS page-aligned size for install calculations
                install_size = self._calculate_aligned_install_size(file_info.size)
                download_size = self._estimate_download_size(file_info)

                breakdown[category]["install"] += install_size
                breakdown[category]["download"] += download_size

        return dict(breakdown)

    def _log_alignment_impact(self, file_analysis: FileAnalysis) -> None:
        """Log the impact of page alignment on install sizes.

        Args:
            file_analysis: File analysis results
        """
        total_actual_size = 0
        total_aligned_size = 0
        small_files_count = 0

        # Collect all files
        all_files: List[FileInfo] = []
        for files_by_type in file_analysis.files_by_type.values():
            all_files.extend(files_by_type)

        for file_info in all_files:
            actual_size = file_info.size
            aligned_size = self._calculate_aligned_install_size(actual_size)

            total_actual_size += actual_size
            total_aligned_size += aligned_size

            if actual_size < self.page_size:
                small_files_count += 1

        overhead = total_aligned_size - total_actual_size
        overhead_mb = overhead / 1024 / 1024
        page_kb = self.page_size // 1024

        platform_name = self.platform.upper()
        log_msg = f"{platform_name} page alignment ({page_kb}KB): +{overhead:,} bytes ({overhead_mb:.1f} MB) overhead"
        logger.info(log_msg)
        logger.info(f"Files smaller than {page_kb}KB: {small_files_count}/{len(all_files)} files")
        total_actual_mb = total_actual_size / 1024 / 1024
        total_aligned_mb = total_aligned_size / 1024 / 1024
        logger.info(f"Actual total: {total_actual_size:,} bytes ({total_actual_mb:.1f} MB)")
        logger.info(f"Aligned total: {total_aligned_size:,} bytes ({total_aligned_mb:.1f} MB)")
