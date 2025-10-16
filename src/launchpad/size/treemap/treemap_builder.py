from __future__ import annotations

import os

from collections import defaultdict
from pathlib import PurePosixPath as PPath
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

# Platform-specific filesystem block sizes (in bytes)
FILESYSTEM_BLOCK_SIZES = {
    "ios": APPLE_FILESYSTEM_BLOCK_SIZE,
    "android": 4 * 1024,
}


class TreemapBuilder:
    def __init__(
        self,
        app_name: str,
        platform: Literal["ios", "android"],
        filesystem_block_size: int | None = None,
        # Optional presentation tweak: collapse one-child directory chains (off by default)
        compress_paths: bool = False,
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] | None = None,
        class_definitions: list[ClassDefinition] | None = None,
        hermes_reports: Dict[str, HermesReport] | None = None,
    ) -> None:
        self.app_name = app_name
        self.platform = platform
        self.binary_analysis_map = binary_analysis_map or {}
        self.class_definitions = class_definitions or []
        self.hermes_reports = hermes_reports or {}
        self.compress_paths = compress_paths

        if filesystem_block_size is not None:
            self.filesystem_block_size = filesystem_block_size
        else:
            self.filesystem_block_size = FILESYSTEM_BLOCK_SIZES.get(platform, 4 * 1024)

        logger.debug(
            f"Using filesystem block size: {self.filesystem_block_size} bytes; compress_paths={self.compress_paths}"
        )

    def build_file_treemap(self, file_analysis: FileAnalysis) -> TreemapResults:
        logger.info("size.treemap.build_file_treemap", extra={"platform": self.platform})

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

        if self.compress_paths:
            root = self._compress_one_child_dirs(root)

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
        ftype = (file_info.file_type or "").lower()
        if ftype == "macho":
            element_builder = MachOElementBuilder(
                binary_analysis_map=self.binary_analysis_map,
                filesystem_block_size=self.filesystem_block_size,
            )
        elif ftype == "dex":
            element_builder = DexElementBuilder(
                class_definitions=self.class_definitions,
                filesystem_block_size=self.filesystem_block_size,
            )
        elif ftype in HERMES_EXTENSIONS:
            element_builder = HermesElementBuilder(
                filesystem_block_size=self.filesystem_block_size,
                hermes_reports=self.hermes_reports,
            )

        element = element_builder.build_element(file_info, display_name)
        if element is None:
            element = default_element_builder.build_element(file_info, display_name)
        return element

    def _build_file_hierarchy(self, file_analysis: FileAnalysis) -> List[TreemapElement]:
        """Build hierarchical file structure using the SINGLE RULE:
        - At each directory node, group items by the *immediate* child segment below that node.
        """
        # Map: directory path -> files directly or indirectly under it
        directory_map: Dict[str, List[FileInfo]] = defaultdict(list)
        root_files: List[FileInfo] = []

        for file_info in file_analysis.files:
            p = PPath(file_info.path)
            if len(p.parts) == 1:
                root_files.append(file_info)
            else:
                directory_map[str(p.parent.as_posix())].append(file_info)

        elements: List[TreemapElement] = []

        # Root-level files
        for file_info in sorted(root_files, key=lambda f: f.path):
            elements.append(self._create_file_element(file_info, PPath(file_info.path).name))

        # dir_structure: each dir -> all files beneath it (including in subdirs)
        dir_structure: Dict[str, List[FileInfo]] = defaultdict(list)

        # Populate dir_structure by walking ancestors
        for dir_path, files in directory_map.items():
            path_obj = PPath(dir_path)
            dir_structure[dir_path].extend(files)
            while len(path_obj.parts) > 1:
                parent = str(path_obj.parent.as_posix())
                dir_structure[parent].extend(files)
                path_obj = path_obj.parent

        # Collect all directory paths to render
        all_dirs: set[str] = set()
        for dir_path in directory_map.keys():
            current = PPath(dir_path)
            while len(current.parts) > 0:
                all_dirs.add(str(current.as_posix()))
                current = current.parent

        def build_directory(dir_path: str) -> TreemapElement:
            """Recursively build a directory node; group by immediate child segment."""
            dir_name = os.path.basename(dir_path.rstrip("/"))
            files_below = dir_structure[dir_path]

            subdirs: Dict[str, List[FileInfo]] = defaultdict(list)
            direct_files: List[FileInfo] = []

            base = PPath(dir_path)
            for file_info in files_below:
                p = PPath(file_info.path)
                if str(p.parent.as_posix()) == dir_path:
                    direct_files.append(file_info)
                else:
                    # SINGLE RULE: attach under the immediate child directory below `dir_path`
                    try:
                        rel = p.relative_to(base)
                    except ValueError:
                        # Shouldn't happen (defensive)
                        continue
                    if not rel.parts:
                        continue
                    immediate = str((base / rel.parts[0]).as_posix())
                    subdirs[immediate].append(file_info)

            children: List[TreemapElement] = []

            # Direct files
            for file_info in sorted(direct_files, key=lambda f: PPath(f.path).name):
                children.append(self._create_file_element(file_info, os.path.basename(file_info.path)))

            # Immediate subdirectories
            for subdir_path in sorted(subdirs.keys()):
                children.append(build_directory(subdir_path))

            total_size = sum(child.size for child in children)

            return TreemapElement(
                name=dir_name or dir_path,  # fall back if basename is empty
                size=total_size,
                type=self._get_directory_type(dir_name, dir_path),
                path=dir_path,
                is_dir=True,
                children=children,
            )

        # Build top-level directories (e.g., "Frameworks", "PlugIns", "javax", etc.)
        top_level_dirs: set[str] = {d for d in all_dirs if len(PPath(d).parts) == 1}
        for dir_path in sorted(top_level_dirs):
            elements.append(build_directory(dir_path))

        return elements

    def _compress_one_child_dirs(self, node: TreemapElement) -> TreemapElement:
        """Optional presentation pass: collapse chains of directories where
        a directory has exactly one child and that child is a directory, and
        the directory has no direct files (i.e., all children are dirs).
        """
        if not node.is_dir or not node.children:
            return node

        # First, compress children
        compressed_children = [self._compress_one_child_dirs(c) for c in node.children]

        # If any direct files exist, don't compress this node
        if any(not c.is_dir for c in compressed_children):
            return node.model_copy(update={"children": compressed_children})

        # Count directory children
        dir_children = [c for c in compressed_children if c.is_dir]

        # If exactly one dir child and no files, merge names: "a" + "/" + "b"
        if len(dir_children) == 1 and len(compressed_children) == 1:
            only = dir_children[0]
            merged_name = f"{node.name}/{only.name}" if node.name else only.name
            # Keep the child's children; size stays the same because it's the sum already
            return only.model_copy(update={"name": merged_name})

        return node.model_copy(update={"children": compressed_children})

    def _get_directory_type(self, directory_name: str, directory_path: str | None = None) -> TreemapType | None:
        """Determine treemap type for a directory."""
        name_lower = (directory_name or "").lower()
        path_lower = (directory_path or "").lower()

        # Cross-platform directory types
        if name_lower in ["assets", "images"]:
            return TreemapType.ASSETS

        # iOS-specific directory types
        if ".appex" in name_lower:
            return TreemapType.EXTENSIONS
        elif ".framework" in name_lower:
            return TreemapType.FRAMEWORKS
        elif ".lproj" in name_lower:
            return TreemapType.RESOURCES
        elif name_lower == "frameworks":
            return TreemapType.FRAMEWORKS
        elif name_lower == "plugins":
            return TreemapType.EXTENSIONS

        # Android-specific directory types
        elif name_lower == "res" or path_lower.startswith("res/"):
            return TreemapType.RESOURCES
        elif name_lower == "lib" or path_lower.startswith("lib/"):
            return TreemapType.NATIVE_LIBRARIES
        elif name_lower in [
            "arm64-v8a",
            "armeabi-v7a",
            "x86",
            "x86_64",
            "mips",
            "mips64",
        ]:
            return TreemapType.NATIVE_LIBRARIES

        return TreemapType.FILES  # Default

    def _calculate_category_breakdown(self, file_analysis: FileAnalysis) -> Dict[str, Dict[str, int]]:
        """Calculate size breakdown by category."""
        breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"size": 0})
        for file_info in file_analysis.files:
            treemap_type = file_info.treemap_type.value
            size = to_nearest_block_size(file_info.size, self.filesystem_block_size)
            breakdown[treemap_type]["size"] += size
        return dict(breakdown)
