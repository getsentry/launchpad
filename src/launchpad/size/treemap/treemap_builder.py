from __future__ import annotations

import os

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Literal

from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.hermes.reporter import HermesReport
from launchpad.size.hermes.utils import HERMES_EXTENSIONS
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapResults, TreemapType
from launchpad.size.treemap.dex_element_builder import DexElementBuilder
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.file_utils import to_nearest_block_size
from launchpad.utils.logging import get_logger

from .default_file_element_builder import DefaultFileElementBuilder
from .hermes_element_builder import HermesElementBuilder
from .macho_element_builder import MachOElementBuilder

logger = get_logger(__name__)


class TreemapBuilder:
    def __init__(
        self,
        app_name: str,
        platform: Literal["ios", "android"],
        download_compression_ratio: float,
        filesystem_block_size: int | None = None,
        # TODO: We should try to move iOS-specific logic out of this class's constructor
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] | None = None,
        class_definitions: list[ClassDefinition] | None = None,
        hermes_reports: Dict[str, HermesReport] | None = None,
    ) -> None:
        self.app_name = app_name
        self.platform = platform
        self.download_compression_ratio = max(0.0, min(1.0, download_compression_ratio))
        self.binary_analysis_map = binary_analysis_map or {}
        self.class_definitions = class_definitions or []
        self.hermes_reports = hermes_reports or {}

        if filesystem_block_size is not None:
            self.filesystem_block_size = filesystem_block_size
        else:
            self.filesystem_block_size = FILESYSTEM_BLOCK_SIZES.get(platform, 4 * 1024)

        logger.debug(f"Using filesystem block size: {self.filesystem_block_size} bytes")
        logger.debug(f"Download compression ratio: {self.download_compression_ratio:.1%}")

    def build_file_treemap(self, file_analysis: FileAnalysis) -> TreemapResults:
        logger.info(f"Building file-based treemap for {self.platform} platform")

        children = self._build_file_hierarchy(file_analysis)

        # Calculate total sizes from children
        total_install_size = sum(child.install_size for child in children)
        total_download_size = sum(child.download_size for child in children)

        root = TreemapElement(
            name=self.app_name,
            install_size=total_install_size,
            download_size=total_download_size,
            element_type=None,
            path=None,
            is_directory=True,  # Root app element is treated as a directory
            children=children,
        )

        category_breakdown = self._calculate_category_breakdown(file_analysis)

        return TreemapResults(
            root=root,
            total_install_size=total_install_size,
            total_download_size=total_download_size,
            file_count=file_analysis.file_count,
            category_breakdown=category_breakdown,
            platform=self.platform,
        )

    def _create_file_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        default_element_builder = DefaultFileElementBuilder(
            download_compression_ratio=self.download_compression_ratio,
            filesystem_block_size=self.filesystem_block_size,
        )

        element_builder: TreemapElementBuilder = default_element_builder
        match file_info.file_type:
            case "macho":
                element_builder = MachOElementBuilder(
                    binary_analysis_map=self.binary_analysis_map,
                    download_compression_ratio=self.download_compression_ratio,
                    filesystem_block_size=self.filesystem_block_size,
                )
            case "dex":
                element_builder = DexElementBuilder(
                    class_definitions=self.class_definitions,
                    download_compression_ratio=self.download_compression_ratio,
                    filesystem_block_size=self.filesystem_block_size,
                )
            case _ if file_info.file_type.lower() in HERMES_EXTENSIONS:
                element_builder = HermesElementBuilder(
                    download_compression_ratio=self.download_compression_ratio,
                    filesystem_block_size=self.filesystem_block_size,
                    hermes_reports=self.hermes_reports,
                )
            case _:
                # Use default element builder for any other file types
                pass

        logger.debug(f"Using {element_builder.__class__.__name__} for {file_info.file_type}")

        element = element_builder.build_element(file_info, display_name)
        if element is None:
            logger.debug(
                f"None returned from {element_builder.__class__.__name__} for {file_info.file_type}, "
                f"using DefaultFileElementBuilder"
            )
            element = default_element_builder.build_element(file_info, display_name)

        return element

    def _build_file_hierarchy(self, file_analysis: FileAnalysis) -> List[TreemapElement]:
        """Build hierarchical file structure from file analysis."""

        # Group files by their full directory structure
        directory_map: Dict[str, List[FileInfo]] = defaultdict(list)
        root_files: List[FileInfo] = []

        for file_info in file_analysis.files:
            path_obj = Path(file_info.path)
            if len(path_obj.parts) == 1:
                # Root level file
                root_files.append(file_info)
            else:
                # File in subdirectory - group by full directory path
                dir_path = str(path_obj.parent)
                directory_map[dir_path].append(file_info)

        elements: List[TreemapElement] = []

        # Add root level files
        for file_info in root_files:
            element = self._create_file_element(file_info, file_info.path)
            elements.append(element)

        # Create a map of all directories and their files
        dir_structure: Dict[str, List[FileInfo]] = defaultdict(list)

        # First pass: organize all files into their respective directories
        for dir_path, files in directory_map.items():
            path_obj = Path(dir_path)
            current_dir = dir_path

            # Add files to their immediate directory
            dir_structure[current_dir].extend(files)

            # Add to parent directories
            while len(path_obj.parts) > 1:
                parent = str(path_obj.parent)
                dir_structure[parent].extend(files)
                current_dir = parent
                path_obj = path_obj.parent

        # Get all unique directory paths
        all_dirs: set[str] = set()
        for dir_path in directory_map.keys():
            path_obj = Path(dir_path)
            # Add all parent directories
            current = path_obj
            while len(current.parts) > 0:
                all_dirs.add(str(current))
                current = current.parent

        logger.debug(f"Found directories: {sorted(all_dirs)}")

        # Second pass: build the directory hierarchy
        def build_directory(dir_path: str) -> TreemapElement:
            dir_name = os.path.basename(dir_path)
            files = dir_structure[dir_path]

            # Group files by subdirectory
            subdirs: Dict[str, List[FileInfo]] = defaultdict(list)
            direct_files: List[FileInfo] = []

            for file_info in files:
                path_obj = Path(file_info.path)
                if str(path_obj.parent) == dir_path:
                    direct_files.append(file_info)
                else:
                    # File is in a subdirectory
                    subdir = str(path_obj.parent)
                    subdirs[subdir].append(file_info)

            # Create child elements
            children: List[TreemapElement] = []

            # Add direct files
            for file_info in direct_files:
                filename = os.path.basename(file_info.path)
                element = self._create_file_element(file_info, filename)
                children.append(element)

            # Add subdirectories
            for subdir_path, _ in subdirs.items():
                subdir_element = build_directory(subdir_path)
                children.append(subdir_element)

            # TODO: should this use stat size?
            total_install_size = sum(child.install_size for child in children)
            total_download_size = sum(child.download_size for child in children)

            return TreemapElement(
                name=dir_name,
                install_size=total_install_size,
                download_size=total_download_size,
                element_type=self._get_directory_type(dir_name),
                path=dir_path,
                is_directory=True,
                children=children,
            )

        # Build top-level directories
        top_level_dirs: set[str] = {d for d in all_dirs if len(Path(d).parts) == 1}
        logger.debug(f"Top level directories: {sorted(top_level_dirs)}")

        for dir_path in sorted(top_level_dirs):
            dir_element = build_directory(dir_path)
            elements.append(dir_element)

        return elements

    def _get_directory_type(self, directory_name: str) -> TreemapType | None:
        """Determine treemap type for a directory."""
        name_lower = directory_name.lower()

        if ".appex" in name_lower:
            return TreemapType.EXTENSIONS
        elif ".framework" in name_lower:
            return TreemapType.FRAMEWORKS
        elif name_lower in ["assets", "images"]:
            return TreemapType.ASSETS
        elif ".lproj" in name_lower:
            return TreemapType.RESOURCES
        elif name_lower == "frameworks":
            return TreemapType.FRAMEWORKS
        elif name_lower == "plugins":
            return TreemapType.EXTENSIONS

        return TreemapType.FILES  # Default to FILES instead of None

    def _calculate_category_breakdown(self, file_analysis: FileAnalysis) -> Dict[str, Dict[str, int]]:
        """Calculate size breakdown by category."""
        breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"install": 0, "download": 0})

        for file_info in file_analysis.files:
            treemap_type = file_info.treemap_type.value
            # Use filesystem block-aligned size for install calculations
            install_size = to_nearest_block_size(file_info.size, self.filesystem_block_size)
            download_size = int(file_info.size * self.download_compression_ratio)

            breakdown[treemap_type]["install"] += install_size
            breakdown[treemap_type]["download"] += download_size

        return dict(breakdown)


# Platform-specific filesystem block sizes (in bytes)
FILESYSTEM_BLOCK_SIZES = {
    "ios": APPLE_FILESYSTEM_BLOCK_SIZE,  # iOS uses 4KB filesystem blocks
    "android": 4 * 1024,  # Android typically uses 4KB as well
}
