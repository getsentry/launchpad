from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.common import FileInfo
from launchpad.size.models.range_mapping import Range
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

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
            return self._build_binary_treemap(display_name, file_info.path, binary_analysis)
        else:
            logger.warning(f"Binary {file_info.path} found but not in binary analysis map")

        # Fallback to default file element if no binary analysis is available
        return None

    def _build_binary_treemap(
        self, name: str, file_path: str, binary_analysis: MachOBinaryAnalysis
    ) -> TreemapElement | None:
        range_map = binary_analysis.range_map
        symbol_info = binary_analysis.symbol_info
        symbol_groups = symbol_info.get_symbols_by_section() if symbol_info else {}

        if range_map is None:
            logger.warning(f"Binary {name} has no range mapping")
            return None

        ranges_by_name: dict[str, list[Range]] = {}
        for range_obj in range_map.ranges:
            # Use the description as the key, fallback to tag value if no description
            range_name = range_obj.description or range_obj.tag.value
            if range_name not in ranges_by_name:
                ranges_by_name[range_name] = []
            ranges_by_name[range_name].append(range_obj)

        # Create child elements for each name
        children: list[TreemapElement] = []
        dyld_children: list[TreemapElement] = []

        logger.debug(f"Processing names: {list(ranges_by_name.keys())}")

        for range_name, ranges in ranges_by_name.items():
            total_size = sum(r.size for r in ranges)

            # Use the first range's tag to determine element type
            first_tag = ranges[0].tag.value

            element_type = TreemapType.EXECUTABLES
            if first_tag.startswith("dyld_"):
                element_type = TreemapType.DYLD
            elif first_tag == "unmapped":
                element_type = TreemapType.UNMAPPED
            elif first_tag == "code_signature":
                element_type = TreemapType.CODE_SIGNATURE
            elif first_tag == "function_starts":
                element_type = TreemapType.FUNCTION_STARTS
            elif first_tag == "external_methods":
                element_type = TreemapType.EXTERNAL_METHODS

            symbol_children = []
            if range_name.startswith("__") and symbol_groups:
                section_symbols = symbol_groups.get(range_name, [])
                symbol_children = self._create_symbol_elements(section_symbols)
            else:
                logger.debug(f"No symbol lookup for range {range_name} (not a section)")

            element = TreemapElement(
                name=range_name,
                install_size=total_size,
                download_size=total_size,  # TODO: add download size
                element_type=element_type,
                path=None,
                is_directory=bool(symbol_children),
                children=symbol_children,
                details={"tag": first_tag, "range_name": range_name},
            )

            # Group DYLD-related load commands under a parent DYLD element
            # Check both the tag and the range_name for DYLD patterns
            is_dyld = first_tag.startswith("dyld_") or range_name.startswith("LC_DYLD_") or "DYLD" in range_name.upper()
            if is_dyld:
                logger.debug(f"Adding {range_name} to DYLD group")
                dyld_children.append(element)
            else:
                logger.debug(f"Adding {range_name} to regular children")
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

        total_size = sum(child.install_size for child in children)
        return TreemapElement(
            name=name,
            install_size=total_size,
            download_size=total_size,
            element_type=TreemapType.EXECUTABLES,
            path=file_path,
            is_directory=True,
            children=children,
            details={},
        )

    def _create_symbol_elements(self, symbols: list[tuple[str, str, int, int]]) -> list[TreemapElement]:
        """Create treemap elements for symbols, grouped by module name with type names as children."""
        modules: dict[str, list[tuple[str, int, int]]] = {}

        for module, name, address, size in symbols:
            if module not in modules:
                modules[module] = []
            modules[module].append((name, address, size))

        module_elements: list[TreemapElement] = []
        for module_name, module_symbols in modules.items():
            symbol_children: list[TreemapElement] = []
            module_total_size = 0

            for name, address, size in module_symbols:
                symbol_element = TreemapElement(
                    name=name,
                    install_size=size,
                    download_size=size,
                    element_type=TreemapType.MODULES,
                    path=None,
                    is_directory=False,
                    children=[],
                    details={"symbol_name": name, "address": address, "size": size},
                )
                symbol_children.append(symbol_element)
                module_total_size += size

            module_element = TreemapElement(
                name=module_name,
                install_size=module_total_size,
                download_size=module_total_size,
                element_type=TreemapType.MODULES,
                path=None,
                is_directory=True,
                children=symbol_children,
                details={"module_name": module_name, "symbol_count": len(module_symbols)},
            )
            module_elements.append(module_element)

        return module_elements
