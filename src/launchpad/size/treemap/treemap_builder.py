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
        filesystem_block_size: int | None = None,
        # TODO: Move iOS-specific logic out of constructor
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] | None = None,
        class_definitions: list[ClassDefinition] | None = None,
        hermes_reports: Dict[str, HermesReport] | None = None,
    ) -> None:
        self.app_name = app_name
        self.platform = platform
        self.binary_analysis_map = binary_analysis_map or {}
        self.class_definitions = class_definitions or []
        self.hermes_reports = hermes_reports or {}

        if filesystem_block_size is not None:
            self.filesystem_block_size = filesystem_block_size
        else:
            self.filesystem_block_size = FILESYSTEM_BLOCK_SIZES.get(platform, 4 * 1024)

        logger.debug(f"Using filesystem block size: {self.filesystem_block_size} bytes")

    def build_file_treemap(self, file_analysis: FileAnalysis) -> TreemapResults:
        logger.info(f"Building file-based treemap for {self.platform} platform")

        children = self._build_file_hierarchy(file_analysis)
        total_size = sum(child.size for child in children)

        root = TreemapElement(
            name=self.app_name,
            size=total_size,
            type=None,
            path=None,
            is_dir=True,
            children=children,
        )

        category_breakdown = self._calculate_category_breakdown(file_analysis)

        return TreemapResults(
            root=root,
            file_count=file_analysis.file_count,
            category_breakdown=category_breakdown,
            platform=self.platform,
        )

    def _create_file_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        default_element_builder = DefaultFileElementBuilder(
            filesystem_block_size=self.filesystem_block_size,
        )

        element_builder: TreemapElementBuilder = default_element_builder
        match file_info.file_type:
            case "macho":
                element_builder = MachOElementBuilder(
                    binary_analysis_map=self.binary_analysis_map,
                    filesystem_block_size=self.filesystem_block_size,
                )
            case "dex":
                element_builder = DexElementBuilder(
                    class_definitions=self.class_definitions,
                    filesystem_block_size=self.filesystem_block_size,
                )
            case _ if file_info.file_type.lower() in HERMES_EXTENSIONS:
                element_builder = HermesElementBuilder(
                    filesystem_block_size=self.filesystem_block_size,
                    hermes_reports=self.hermes_reports,
                )
            case _:
                pass

        element = element_builder.build_element(file_info, display_name)
        if element is None:
            element = default_element_builder.build_element(file_info, display_name)
        return element

    def _build_file_hierarchy(self, file_analysis: FileAnalysis) -> List[TreemapElement]:
        """Build hierarchical file structure from file analysis."""
        # Group files by their immediate directory
        directory_map: Dict[str, List[FileInfo]] = defaultdict(list)
        root_files: List[FileInfo] = []

        for file_info in file_analysis.files:
            path_obj = Path(file_info.path)
            if len(path_obj.parts) == 1:
                root_files.append(file_info)
            else:
                dir_path = str(path_obj.parent)
                directory_map[dir_path].append(file_info)

        elements: List[TreemapElement] = []

        # Root-level files
        for file_info in sorted(root_files, key=lambda f: f.path):
            element = self._create_file_element(file_info, Path(file_info.path).name)
            elements.append(element)

        # dir_structure maps each directory -> all files beneath it (including in subdirs)
        dir_structure: Dict[str, List[FileInfo]] = defaultdict(list)

        # Pull files up into all ancestors to make recursive building cheap
        for dir_path, files in directory_map.items():
            path_obj = Path(dir_path)
            # Add to immediate dir
            dir_structure[dir_path].extend(files)
            # Add to all parent dirs up to (but not beyond) the top-level directory
            while len(path_obj.parts) > 1:
                parent = str(path_obj.parent)
                dir_structure[parent].extend(files)
                path_obj = path_obj.parent

        # Collect all directory paths
        all_dirs: set[str] = set()
        for dir_path in directory_map.keys():
            path_obj = Path(dir_path)
            current = path_obj
            while len(current.parts) > 0:
                all_dirs.add(str(current))
                current = current.parent

        def build_directory(dir_path: str) -> TreemapElement:
            """Recursively build a directory node, ensuring only immediate children render under this node."""
            dir_name = os.path.basename(dir_path)
            files_below = dir_structure[dir_path]

            # Partition into direct files and immediate child directories
            subdirs: Dict[str, List[FileInfo]] = defaultdict(list)
            direct_files: List[FileInfo] = []

            base = Path(dir_path)

            for file_info in files_below:
                p = Path(file_info.path)
                if str(p.parent) == dir_path:
                    direct_files.append(file_info)
                else:
                    # KEY FIX: group by the *immediate* child directory under dir_path
                    try:
                        rel = p.relative_to(base)
                    except ValueError:
                        # Not actually under this dir (shouldn't happen since we pre-filled), skip
                        continue
                    if not rel.parts:
                        continue
                    immediate = str(base / rel.parts[0])
                    subdirs[immediate].append(file_info)

            children: List[TreemapElement] = []

            # Add direct files
            for file_info in sorted(direct_files, key=lambda f: Path(f.path).name):
                filename = os.path.basename(file_info.path)
                children.append(self._create_file_element(file_info, filename))

            # Add immediate subdirectories (recursively)
            for subdir_path in sorted(subdirs.keys()):
                children.append(build_directory(subdir_path))

            total_size = sum(child.size for child in children)

            return TreemapElement(
                name=dir_name,
                size=total_size,
                type=self._get_directory_type(dir_name),
                path=dir_path,
                is_dir=True,
                children=children,
            )

        # Build top-level directories (e.g., "Frameworks", "PlugIns", etc.)
        top_level_dirs: set[str] = {d for d in all_dirs if len(Path(d).parts) == 1}
        for dir_path in sorted(top_level_dirs):
            elements.append(build_directory(dir_path))

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

        return TreemapType.FILES  # Default

    def _calculate_category_breakdown(self, file_analysis: FileAnalysis) -> Dict[str, Dict[str, int]]:
        """Calculate size breakdown by category."""
        breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"size": 0})
        for file_info in file_analysis.files:
            treemap_type = file_info.treemap_type.value
            size = to_nearest_block_size(file_info.size, self.filesystem_block_size)
            breakdown[treemap_type]["size"] += size
        return dict(breakdown)


# Platform-specific filesystem block sizes (in bytes)
FILESYSTEM_BLOCK_SIZES = {
    "ios": APPLE_FILESYSTEM_BLOCK_SIZE,
    "android": 4 * 1024,
}
