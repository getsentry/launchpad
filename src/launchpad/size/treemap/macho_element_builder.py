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

        children: list[TreemapElement] = []
        dyld_children: list[TreemapElement] = []

        logger.debug(f"Processing names: {list(ranges_by_name.keys())}")

        # Calculate initial section sizes
        # When we eventually loop over individual types, we subtract the type size from the section
        # to avoid double-counting.
        section_sizes: dict[str, int] = {}
        for range_name, ranges in ranges_by_name.items():
            total_size = sum(r.size for r in ranges)
            section_sizes[range_name] = total_size

        symbol_children: list[TreemapElement] = []
        section_subtractions: dict[str, int] = {}

        if symbol_info:
            # Group Swift symbols by their module
            swift_modules: dict[str, list[tuple[str, int]]] = {}
            for group in symbol_info.swift_type_groups:
                module = group.module
                if module not in swift_modules:
                    swift_modules[module] = []
                swift_modules[module].append((group.type_name, group.total_size))

                for symbol in group.symbols:
                    if symbol.section:
                        section_name = str(symbol.section.name)
                        section_subtractions[section_name] = section_subtractions.get(section_name, 0) + symbol.size

            # Create Swift module elements
            for module_name, type_groups in swift_modules.items():
                module_children: list[TreemapElement] = []
                module_total_size = 0

                for type_name, total_size in type_groups:
                    type_element = TreemapElement(
                        name=type_name,
                        install_size=total_size,
                        download_size=total_size,
                        element_type=TreemapType.MODULES,
                        path=None,
                        is_directory=False,
                        children=[],
                    )
                    module_children.append(type_element)
                    module_total_size += total_size

                module_element = TreemapElement(
                    name=module_name,
                    install_size=module_total_size,
                    download_size=module_total_size,
                    element_type=TreemapType.MODULES,
                    path=None,
                    is_directory=True,
                    children=module_children,
                )
                symbol_children.append(module_element)

            # Group ObjC symbols by class
            objc_classes: dict[str, list[tuple[str, int]]] = {}
            for group in symbol_info.objc_type_groups:
                class_name = group.class_name
                if class_name not in objc_classes:
                    objc_classes[class_name] = []
                method_name = group.method_name or "class"
                objc_classes[class_name].append((method_name, group.total_size))

                for symbol in group.symbols:
                    if symbol.section:
                        section_name = str(symbol.section.name)
                        section_subtractions[section_name] = section_subtractions.get(section_name, 0) + symbol.size

            # Create ObjC class elements
            for class_name, method_groups in objc_classes.items():
                class_children: list[TreemapElement] = []
                class_total_size = 0

                for method_name, total_size in method_groups:
                    method_element = TreemapElement(
                        name=method_name,
                        install_size=total_size,
                        download_size=total_size,
                        element_type=TreemapType.MODULES,
                        path=None,
                        is_directory=False,
                        children=[],
                    )
                    class_children.append(method_element)
                    class_total_size += total_size

                class_element = TreemapElement(
                    name=class_name,
                    install_size=class_total_size,
                    download_size=class_total_size,
                    element_type=TreemapType.MODULES,
                    path=None,
                    is_directory=True,
                    children=class_children,
                )
                symbol_children.append(class_element)

        # Create section elements (excluding those with zero or negative size)
        for range_name, ranges in ranges_by_name.items():
            original_size = section_sizes.get(range_name, 0)
            subtraction = section_subtractions.get(range_name, 0)
            adjusted_size = original_size - subtraction

            if adjusted_size <= 0:
                logger.debug(
                    f"Skipping section {range_name} with adjusted size {adjusted_size} (original: {original_size}, subtraction: {subtraction})"
                )
                continue

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

            element = TreemapElement(
                name=range_name,
                install_size=adjusted_size,
                download_size=adjusted_size,  # TODO: add download size
                element_type=element_type,
                path=None,
                is_directory=False,
                children=[],
                details={"tag": first_tag, "range_name": range_name, "adjusted_size": adjusted_size},
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

        total_size = sum(child.install_size for child in children) + sum(
            child.install_size for child in symbol_children
        )
        return TreemapElement(
            name=name,
            install_size=total_size,
            download_size=total_size,
            element_type=TreemapType.EXECUTABLES,
            path=file_path,
            is_directory=True,
            children=children + symbol_children,
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
