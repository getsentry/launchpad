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


class PageSizeConfig:
    """Configuration for page alignment calculations across platforms and components."""

    def __init__(
        self,
        default_page_size: int,
        native_page_size: Optional[int] = None,
        description: str = "custom",
    ) -> None:
        """Initialize page size configuration.

        Args:
            default_page_size: Page size for most file types (bytes)
            native_page_size: Page size for native code/libraries (bytes), or None to use default
            description: Human-readable description of this configuration
        """
        self.default_page_size = default_page_size
        self.native_page_size = native_page_size or default_page_size
        self.description = description

    @classmethod
    def ios_modern(cls) -> "PageSizeConfig":
        """iOS configuration for modern devices (iOS 14+)."""
        return cls(
            default_page_size=16 * 1024,  # 16KB for all files
            description="iOS modern (16KB pages)",
        )

    @classmethod
    def android_legacy(cls) -> "PageSizeConfig":
        """Android configuration for devices without 16KB page support."""
        return cls(
            default_page_size=4 * 1024,  # 4KB for all files
            description="Android legacy (4KB pages)",
        )

    @classmethod
    def android_mixed(cls) -> "PageSizeConfig":
        """Android configuration for devices with mixed page size support.

        Some Android devices support 16KB pages for native code but still use 4KB
        for other components. This is common during the 16KB rollout phase.
        """
        return cls(
            default_page_size=4 * 1024,  # 4KB for most files
            native_page_size=16 * 1024,  # 16KB for native libraries
            description="Android mixed (4KB default, 16KB native)",
        )

    @classmethod
    def android_modern(cls) -> "PageSizeConfig":
        """Android configuration for fully 16KB-enabled devices."""
        return cls(
            default_page_size=16 * 1024,  # 16KB for all files
            description="Android modern (16KB pages)",
        )

    def get_page_size_for_file(self, file_info: FileInfo) -> int:
        """Get appropriate page size for a specific file.

        Args:
            file_info: File information

        Returns:
            Page size in bytes for this file type
        """
        # Check if this is native code that might use different page alignment
        if self._is_native_code(file_info):
            return self.native_page_size
        return self.default_page_size

    def _is_native_code(self, file_info: FileInfo) -> bool:
        """Check if a file is native code that might use different page alignment.

        Args:
            file_info: File information

        Returns:
            True if this file is likely native code
        """
        file_type = file_info.file_type.lower()
        path_lower = file_info.path.lower()

        # Native libraries and executables
        if file_type in ["so", "dylib"]:
            return True

        # Framework executables
        if ".framework" in path_lower and file_type == "":
            return True

        # Main executable (no extension)
        if file_type == "" and "/" not in file_info.path:
            return True

        return False


# Predefined page size configurations for common scenarios
DEFAULT_PAGE_CONFIGS = {
    "ios": PageSizeConfig.ios_modern(),
    "android": PageSizeConfig.android_legacy(),  # Conservative default
    "android-mixed": PageSizeConfig.android_mixed(),
    "android-modern": PageSizeConfig.android_modern(),
    "unknown": PageSizeConfig.android_legacy(),  # Conservative fallback
}


class TreemapBuilder:
    """Builder for creating treemap structures from file analysis data.

    The TreemapBuilder supports flexible page size configuration to handle the complexity
    of different platforms and the ongoing Android 16KB page size rollout.

    Examples:
        # iOS app (uses 16KB pages for all files)
        builder = TreemapBuilder(app_name="MyApp", platform="ios")

        # Android app on legacy device (4KB pages for all files)
        builder = TreemapBuilder(app_name="MyApp", platform="android")

        # Android app with mixed page support (4KB default, 16KB for native code)
        mixed_config = PageSizeConfig.android_mixed()
        builder = TreemapBuilder(app_name="MyApp", platform="android", page_config=mixed_config)

        # Android app on fully 16KB-enabled device
        modern_config = PageSizeConfig.android_modern()
        builder = TreemapBuilder(app_name="MyApp", platform="android", page_config=modern_config)

        # Custom page configuration for specific scenarios
        custom_config = PageSizeConfig(
            default_page_size=8 * 1024,   # 8KB for most files
            native_page_size=16 * 1024,   # 16KB for native libraries
            description="custom 8KB/16KB split"
        )
        builder = TreemapBuilder(app_name="MyApp", platform="custom", page_config=custom_config)
    """

    def __init__(
        self,
        app_name: str = "App",
        platform: str = "unknown",
        page_config: Optional[PageSizeConfig] = None,
    ) -> None:
        """Initialize the treemap builder.

        Args:
            app_name: Name of the root app element
            platform: Platform name (ios, android, etc.) - used for default page config
            page_config: Explicit page size configuration, or None to use platform default
        """
        self.app_name = app_name
        self.platform = platform

        # Use explicit page config or fall back to platform default
        if page_config is not None:
            self.page_config = page_config
        else:
            self.page_config = DEFAULT_PAGE_CONFIGS.get(platform, DEFAULT_PAGE_CONFIGS["unknown"])

        logger.debug(f"Using page configuration: {self.page_config.description}")

    @property
    def page_size(self) -> int:
        """Default page size for backward compatibility."""
        return self.page_config.default_page_size

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

    def _calculate_aligned_install_size(self, file_info: FileInfo) -> int:
        """Calculate the actual install size considering file-specific page alignment.

        Args:
            file_info: File information including size and type

        Returns:
            Install size rounded up to nearest page boundary for this file type
        """
        file_size = file_info.size
        if file_size == 0:
            return 0

        # Get appropriate page size for this file
        page_size = self.page_config.get_page_size_for_file(file_info)

        # Round up to nearest page boundary
        # Formula: ((size - 1) // page_size + 1) * page_size
        return ((file_size - 1) // page_size + 1) * page_size

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
        install_size = self._calculate_aligned_install_size(file_info)
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
                install_size = self._calculate_aligned_install_size(file_info)
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

        # Track stats by page size for mixed configurations
        page_size_stats: Dict[int, Dict[str, int]] = defaultdict(lambda: {"count": 0, "actual": 0, "aligned": 0})

        # Collect all files
        all_files: List[FileInfo] = []
        for files_by_type in file_analysis.files_by_type.values():
            all_files.extend(files_by_type)

        for file_info in all_files:
            actual_size = file_info.size
            aligned_size = self._calculate_aligned_install_size(file_info)
            page_size = self.page_config.get_page_size_for_file(file_info)

            total_actual_size += actual_size
            total_aligned_size += aligned_size

            # Track by page size
            page_size_stats[page_size]["count"] += 1
            page_size_stats[page_size]["actual"] += actual_size
            page_size_stats[page_size]["aligned"] += aligned_size

            if actual_size < page_size:
                small_files_count += 1

        overhead = total_aligned_size - total_actual_size
        overhead_mb = overhead / 1024 / 1024

        # Log overall impact
        platform_name = self.platform.upper()
        overhead_msg = f"{platform_name} page alignment ({self.page_config.description}): "
        overhead_msg += f"+{overhead:,} bytes ({overhead_mb:.1f} MB) overhead"
        logger.info(overhead_msg)

        # Log detailed breakdown for mixed configurations
        if len(page_size_stats) > 1:
            logger.info("Page size breakdown:")
            for page_size, stats in sorted(page_size_stats.items()):
                page_kb = page_size // 1024
                page_overhead = stats["aligned"] - stats["actual"]
                page_overhead_mb = page_overhead / 1024 / 1024
                breakdown_msg = f"  {page_kb}KB pages: {stats['count']} files, "
                breakdown_msg += f"+{page_overhead:,} bytes ({page_overhead_mb:.1f} MB)"
                logger.info(breakdown_msg)

        # Overall file size stats
        default_page_kb = self.page_config.default_page_size // 1024
        small_files_msg = f"Files smaller than default page size ({default_page_kb}KB): "
        small_files_msg += f"{small_files_count}/{len(all_files)} files"
        logger.info(small_files_msg)

        total_actual_mb = total_actual_size / 1024 / 1024
        total_aligned_mb = total_aligned_size / 1024 / 1024
        logger.info(f"Actual total: {total_actual_size:,} bytes ({total_actual_mb:.1f} MB)")
        logger.info(f"Aligned total: {total_aligned_size:,} bytes ({total_aligned_mb:.1f} MB)")
