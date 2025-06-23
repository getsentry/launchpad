from launchpad.models.apple import MachOBinaryAnalysis

from ...models.common import FileInfo
from ...models.range_mapping import Range, RangeMap
from ...models.treemap import TreemapElement, TreemapType
from ..logging import get_logger
from .treemap_element_builder import TreemapElementBuilder

logger = get_logger(__name__)


class MachOElementBuilder(TreemapElementBuilder):

    def __init__(
        self,
        download_compression_ratio: float,
        filesystem_block_size: int,
        binary_analysis_map: dict[str, MachOBinaryAnalysis],
    ) -> None:
        super().__init__(
            download_compression_ratio=download_compression_ratio, filesystem_block_size=filesystem_block_size
        )
        self.binary_analysis_map = binary_analysis_map

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        if file_info.path in self.binary_analysis_map:
            binary_analysis = self.binary_analysis_map[file_info.path]
            if binary_analysis.range_map is not None:
                # Create a binary treemap with sections
                return self._build_binary_treemap(binary_analysis.range_map, display_name, file_info.path)
            else:
                logger.warning(f"Binary {file_info.path} found but has no range mapping")
        else:
            logger.warning(f"Binary {file_info.path} found but not in binary analysis map")

        # Fallback to default file element if no binary analysis is available
        return None

    def _build_binary_treemap(self, range_map: RangeMap, name: str, binary_path: str | None = None) -> TreemapElement:
        # Group ranges by tag
        ranges_by_tag: dict[str, list[Range]] = {}
        for range_obj in range_map.ranges:
            tag = range_obj.tag.value
            if tag not in ranges_by_tag:
                ranges_by_tag[tag] = []
            ranges_by_tag[tag].append(range_obj)

        # Create child elements for each tag
        children: list[TreemapElement] = []
        dyld_children: list[TreemapElement] = []

        logger.debug(f"Processing tags: {list(ranges_by_tag.keys())}")

        for tag, ranges in ranges_by_tag.items():
            total_size = sum(r.size for r in ranges)

            # Determine element type based on tag
            element_type = TreemapType.EXECUTABLES  # Default
            if tag.startswith("dyld_"):
                element_type = TreemapType.DYLD
            elif tag == "unmapped":
                element_type = TreemapType.UNMAPPED
            elif tag == "code_signature":
                element_type = TreemapType.CODE_SIGNATURE
            elif tag == "function_starts":
                element_type = TreemapType.FUNCTION_STARTS
            elif tag == "external_methods":
                element_type = TreemapType.EXTERNAL_METHODS

            element = TreemapElement(
                name=tag,
                install_size=total_size,
                download_size=total_size,  # Binary sections don't compress
                element_type=element_type,
                path=None,
                is_directory=False,
                children=[],
                details={"tag": tag},
            )

            # Group DYLD-related tags under a parent DYLD element
            if tag.startswith("dyld_"):
                logger.debug(f"Adding {tag} to DYLD group")
                dyld_children.append(element)
            else:
                logger.debug(f"Adding {tag} to regular children")
                children.append(element)

        # Create parent DYLD element if we have DYLD children
        if dyld_children:
            dyld_total_size = sum(child.install_size for child in dyld_children)
            dyld_element = TreemapElement(
                name="DYLD",
                install_size=dyld_total_size,
                download_size=dyld_total_size,
                element_type=TreemapType.DYLD,
                path=None,
                is_directory=True,
                children=dyld_children,
                details={"tag": "dyld"},
            )
            children.append(dyld_element)

        # Add unmapped regions if any
        if range_map.unmapped_size > 0:
            children.append(
                TreemapElement(
                    name="Unmapped",
                    install_size=int(range_map.unmapped_size),
                    download_size=int(range_map.unmapped_size),
                    element_type=TreemapType.UNMAPPED,
                    path=None,
                    is_directory=False,
                    children=[],
                    details={},
                )
            )

        # Create root element
        total_size = sum(child.install_size for child in children)
        return TreemapElement(
            name=name,
            install_size=total_size,
            download_size=total_size,
            element_type=TreemapType.EXECUTABLES,
            path=binary_path,
            is_directory=True,
            children=children,
            details={},
        )
