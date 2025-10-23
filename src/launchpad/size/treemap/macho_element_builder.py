from __future__ import annotations

from typing import Dict, List, TypedDict

from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.binary_component import BinaryTag
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.symbols.partitioner import SymbolInfo
from launchpad.size.symbols.types import SwiftSymbolTypeGroup
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class _SwiftTypeNode(TypedDict):
    """Internal helper node for building a nested Swift-type tree."""

    children: Dict[str, "_SwiftTypeNode"]
    self_size: int  # bytes that belong only to *this* type
    type_name: str


class MachOElementBuilder(TreemapElementBuilder):
    def __init__(
        self,
        filesystem_block_size: int,
        binary_analysis_map: Dict[str, MachOBinaryAnalysis],
    ) -> None:
        super().__init__(
            filesystem_block_size=filesystem_block_size,
        )
        self.binary_analysis_map = binary_analysis_map

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        """Entry-point: build a TreemapElement for one Mach-O."""
        if file_info.path not in self.binary_analysis_map:
            logger.warning("Binary %s found but not in binary analysis map", file_info.path)
            return None

        logger.debug(f"Building treemap for {display_name}")

        children = self._build_binary_treemap(
            binary_analysis=self.binary_analysis_map[file_info.path],
        )
        if children is None:
            logger.warning("No children found for %s", display_name)
            return None

        self._assert_element_size(file_info, display_name, children)

        return TreemapElement(
            name=display_name,
            size=file_info.size,
            type=TreemapType.EXECUTABLES,
            path=file_info.path,
            is_dir=False,
            children=children,
        )

    def _assert_element_size(self, file_info: FileInfo, display_name: str, children: List[TreemapElement]) -> None:
        total_child_size = sum(element.size for element in children)
        size_diff = file_info.size - total_child_size
        size_diff_abs = abs(size_diff)
        size_diff_percent = (size_diff_abs / file_info.size) * 100 if file_info.size > 0 else 0

        if size_diff != 0:
            logger.warning(f"Size mismatch for {display_name}:")
            logger.warning(f"  File size: {file_info.size:,} bytes")
            logger.warning(f"  Treemap total: {total_child_size:,} bytes")

            if children:
                logger.warning(f"  Treemap breakdown ({len(children)} top-level elements):")
                for child in children:
                    logger.warning(f"    {child.name}: {child.size:,} bytes ({child.type})")

            if size_diff > 0:
                logger.warning(f"  Difference: {size_diff_abs:,} bytes MISSING from treemap ({size_diff_percent:.2f}%)")
            else:
                logger.warning(
                    f"  Difference: {size_diff_abs:,} bytes OVER-COUNTED in treemap ({size_diff_percent:.2f}%)"
                )

    def _build_binary_treemap(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement] | None:
        binary_children: List[TreemapElement] = []
        section_subtractions: Dict[str, int] = {}

        if binary_analysis.symbol_info:
            # Build symbol-based treemap elements
            self._add_swift_symbols(binary_analysis.symbol_info, binary_children, section_subtractions)
            self._add_objc_symbols(binary_analysis.symbol_info, binary_children, section_subtractions)
            self._add_other_symbols(binary_analysis.symbol_info, binary_children, section_subtractions)

        # Add binary metadata components
        metadata_children = self._build_metadata_components(binary_analysis)
        binary_children.extend(metadata_children)

        # Add raw segments/sections (minus symbol bytes)
        self._add_segments(binary_analysis, binary_children, section_subtractions)

        # Add unmapped region if present
        self._add_unmapped_region(binary_analysis, binary_children)

        return binary_children

    def _add_swift_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        """Process Swift symbols and add them to the treemap as nested module/type hierarchy."""
        if not symbol_info.swift_type_groups:
            return

        # Bucket groups by Swift module
        swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
        for grp in symbol_info.swift_type_groups:
            swift_modules.setdefault(grp.module, []).append(grp)

            # Track section usage for symbol bytes
            for sym in grp.symbols:
                if sym.section_name:
                    segment_name = sym.segment_name or "unknown"
                    unique_sec = f"{segment_name}.{sym.section_name}"
                    section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

        # For every module, build a nested tree
        for module_name, type_groups in swift_modules.items():
            # Build a forward tree where each node owns *only* the bytes
            # that belong to that concrete type (self_size).
            type_tree: Dict[str, _SwiftTypeNode] = {}

            def _ensure(node_map: Dict[str, _SwiftTypeNode], name: str) -> _SwiftTypeNode:
                if name not in node_map:
                    node_map[name] = {
                        "children": {},
                        "self_size": 0,
                        "type_name": name,
                    }
                return node_map[name]

            for grp in type_groups:
                comps = grp.components

                # Strip leading module name if present
                if comps and comps[0] == module_name:
                    comps = comps[1:]

                # Drop segments that don't look like type identifiers
                comps = [c for c in comps if c and c[0].isupper()]
                if not comps:
                    continue

                # Walk / create the tree path, accumulating only in the leaf
                cur = type_tree
                for idx, comp in enumerate(comps):
                    node = _ensure(cur, comp)
                    if idx == len(comps) - 1:  # leaf for this group
                        node["self_size"] += grp.total_size
                    cur = node["children"]

            # Walk the finished tree bottom-up once to compute totals and
            # convert to TreemapElement objects.
            def _tree_to_treemap(node_map: Dict[str, _SwiftTypeNode]) -> List[TreemapElement]:
                elems: List[TreemapElement] = []

                for node in node_map.values():
                    # recurse first
                    child_elems = _tree_to_treemap(node["children"])

                    # If this type has its own bytes *and* nested types, surface the
                    # bytes as a pseudo-child so the treemap can render them.
                    if node["self_size"] > 0 and child_elems:
                        self_elem = TreemapElement(
                            name=node["type_name"],
                            size=node["self_size"],
                            type=TreemapType.MODULES,
                            path=None,
                            is_dir=False,
                            children=[],
                        )
                        child_elems.append(self_elem)
                        # after adding the pseudo-child, the parent's size is just
                        # the sum of *all* children
                        total_size = sum(c.size for c in child_elems)
                    else:
                        # leaf, or container with no own bytes
                        total_size = node["self_size"] + sum(c.size for c in child_elems)

                    elems.append(
                        TreemapElement(
                            name=node["type_name"],
                            size=total_size,
                            type=TreemapType.MODULES,
                            path=None,
                            is_dir=False,
                            children=child_elems,
                        )
                    )

                return elems

            module_children = _tree_to_treemap(type_tree)
            module_total_size = sum(c.size for c in module_children)

            binary_children.append(
                TreemapElement(
                    name=module_name,
                    size=module_total_size,
                    type=TreemapType.MODULES,
                    path=None,
                    is_dir=False,
                    children=module_children,
                )
            )

    def _add_objc_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        """Process Objective-C symbols and add them to the treemap as class/method hierarchy."""
        if not symbol_info.objc_type_groups:
            return

        objc_classes: Dict[str, List[tuple[str, int]]] = {}
        for grp in symbol_info.objc_type_groups:
            objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", grp.total_size))
            for sym in grp.symbols:
                if sym.section_name:
                    if not sym.segment_name:
                        logger.warning("Symbol %s has no segment name", sym.mangled_name)
                        continue

                    segment_name = sym.segment_name or "unknown"
                    unique_sec = f"{segment_name}.{sym.section_name}"
                    section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

        for cls_name, meths in objc_classes.items():
            meth_elems: List[TreemapElement] = [
                TreemapElement(
                    name=meth_name,
                    size=size,
                    type=TreemapType.MODULES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
                for meth_name, size in meths
            ]
            binary_children.append(
                TreemapElement(
                    name=cls_name,
                    size=sum(m.size for m in meth_elems),
                    type=TreemapType.MODULES,
                    path=None,
                    is_dir=False,
                    children=meth_elems,
                )
            )

    def _add_other_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        """Process other symbols (C++, C functions, compiler-generated) and group them under 'Other Symbols'."""
        other_symbols_children: List[TreemapElement] = []
        total_other_symbols_size = 0

        # C++ symbols
        if symbol_info.cpp_type_groups:
            cpp_symbols_with_size = []
            for grp in symbol_info.cpp_type_groups:
                cpp_symbols_with_size.extend([sym for sym in grp.symbols if sym.size > 0])
                # Track section usage
                for sym in grp.symbols:
                    if sym.section_name:
                        segment_name = sym.segment_name or "unknown"
                        unique_sec = f"{segment_name}.{sym.section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

            if cpp_symbols_with_size:
                cpp_size = sum(sym.size for sym in cpp_symbols_with_size)
                total_other_symbols_size += cpp_size
                # Limit to top 50 to avoid overwhelming display
                cpp_symbols_with_size.sort(key=lambda s: s.size, reverse=True)
                top_cpp_symbols = cpp_symbols_with_size[:50]
                cpp_symbol_children: List[TreemapElement] = [
                    TreemapElement(
                        name=sym.mangled_name,
                        size=sym.size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],
                    )
                    for sym in top_cpp_symbols
                ]
                other_symbols_children.append(
                    TreemapElement(
                        name="C++",
                        size=cpp_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=cpp_symbol_children,
                    )
                )

        # Compiler-generated symbols
        if symbol_info.compiler_generated_symbols:
            compiler_syms_with_size = [sym for sym in symbol_info.compiler_generated_symbols if sym.size > 0]
            if compiler_syms_with_size:
                # Track section usage
                for sym in compiler_syms_with_size:
                    if sym.section_name:
                        segment_name = sym.segment_name or "unknown"
                        unique_sec = f"{segment_name}.{sym.section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

                compiler_size = sum(sym.size for sym in compiler_syms_with_size)
                total_other_symbols_size += compiler_size
                # Limit to top 50 to avoid overwhelming display
                compiler_syms_with_size.sort(key=lambda s: s.size, reverse=True)
                top_compiler_syms = compiler_syms_with_size[:50]
                compiler_sym_children: List[TreemapElement] = [
                    TreemapElement(
                        name=sym.mangled_name,
                        size=sym.size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],
                    )
                    for sym in top_compiler_syms
                ]
                other_symbols_children.append(
                    TreemapElement(
                        name="Compiler Generated",
                        size=compiler_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=compiler_sym_children,
                    )
                )

        # C functions and other symbols
        if symbol_info.other_symbols:
            other_symbols_with_size = [sym for sym in symbol_info.other_symbols if sym.size > 0]
            if other_symbols_with_size:
                # Track section usage
                for sym in other_symbols_with_size:
                    if sym.section_name:
                        segment_name = sym.segment_name or "unknown"
                        unique_sec = f"{segment_name}.{sym.section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

                c_symbols_size = sum(sym.size for sym in other_symbols_with_size)
                total_other_symbols_size += c_symbols_size
                # Limit to top 50 to avoid overwhelming display
                other_symbols_with_size.sort(key=lambda s: s.size, reverse=True)
                top_other_symbols = other_symbols_with_size[:50]
                c_symbol_children: List[TreemapElement] = [
                    TreemapElement(
                        name=sym.mangled_name,
                        size=sym.size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],
                    )
                    for sym in top_other_symbols
                ]
                other_symbols_children.append(
                    TreemapElement(
                        name="C Functions",
                        size=c_symbols_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=c_symbol_children,
                    )
                )

        # Add the "Other Symbols" parent node if we have any children
        if other_symbols_children:
            binary_children.append(
                TreemapElement(
                    name="Other Symbols",
                    size=total_other_symbols_size,
                    type=TreemapType.MODULES,
                    path=None,
                    is_dir=False,
                    children=other_symbols_children,
                )
            )

    def _add_segments(
        self,
        binary_analysis: MachOBinaryAnalysis,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        """Process raw segments/sections (minus symbol bytes) and add them to the treemap."""
        for segment in binary_analysis.segments:
            segment_name = segment.name
            segment_children: List[TreemapElement] = []

            if segment.sections:
                for section in segment.sections:
                    section_name = section.name
                    section_size = section.size

                    if section_size == 0:
                        logger.debug(f"Skipping section {section_name} with zero size")
                        continue

                    # Calculate adjusted section size after symbol subtraction
                    unique_sec = f"{segment_name}.{section_name}"
                    subtraction = section_subtractions.get(unique_sec, 0)

                    # Ensure we're not subtracting more than the section actually contains
                    if subtraction > section_size:
                        logger.warning(
                            f"Section {unique_sec}: symbol bytes ({subtraction:,}) "
                            f"exceed section size ({section_size:,}). Capping to section size."
                        )
                        subtraction = section_size

                    adjusted = section_size - subtraction
                    if adjusted <= 0:
                        logger.debug(
                            f"Skipping section {unique_sec} - no remaining size {adjusted} after symbol subtraction"
                        )
                        continue

                    # Categorize the section and create treemap element
                    tag = self._categorize_section(section_name, segment_name) or BinaryTag.OTHER
                    segment_children.append(
                        TreemapElement(
                            name=section_name,
                            size=adjusted,
                            type=self._get_element_type_from_tag(tag),
                            path=None,
                            is_dir=False,
                            children=[],
                        )
                    )

            if segment_name == "__LINKEDIT":
                dyld_children = self._build_dyld_load_command_children(binary_analysis)
                segment_children.extend(dyld_children)

            # Calculate actual segment size in treemap:
            # Start with sum of section children we're displaying
            displayed_section_size = sum(child.size for child in segment_children)

            # Add any segment overhead (segment size - sum of all section sizes)
            total_section_size = sum(section.size for section in segment.sections) if segment.sections else 0
            segment_overhead = segment.size - total_section_size

            actual_segment_size = displayed_section_size + segment_overhead

            if actual_segment_size > 0:
                binary_children.append(
                    TreemapElement(
                        name=segment_name,
                        size=actual_segment_size,
                        type=TreemapType.EXECUTABLES,
                        path=None,
                        is_dir=False,
                        children=segment_children,
                    )
                )

    def _add_unmapped_region(self, binary_analysis: MachOBinaryAnalysis, binary_children: List[TreemapElement]) -> None:
        """Add an explicit 'Unmapped' region if there are unaccounted bytes."""
        total_accounted = sum(c.size for c in binary_children)
        if binary_analysis.executable_size > total_accounted:
            unaccounted = binary_analysis.executable_size - total_accounted
            binary_children.append(
                TreemapElement(
                    name="Unmapped",
                    size=unaccounted,
                    type=TreemapType.UNMAPPED,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

    def _build_metadata_components(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement]:
        """Build treemap elements for binary metadata (headers, load commands, etc.)."""
        metadata_children: List[TreemapElement] = []

        if binary_analysis.header_size > 0:
            metadata_children.append(
                TreemapElement(
                    name="Mach-O Header",
                    size=binary_analysis.header_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if binary_analysis.load_commands:
            load_command_children: List[TreemapElement] = []
            for lc in binary_analysis.load_commands:
                load_command_children.append(
                    TreemapElement(
                        name=lc.name,
                        size=lc.size,
                        type=TreemapType.EXECUTABLES,
                        path=None,
                        is_dir=False,
                        children=[],
                    )
                )

            total_lc_size = sum(lc.size for lc in binary_analysis.load_commands)
            metadata_children.append(
                TreemapElement(
                    name="Load Commands",
                    size=total_lc_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=load_command_children,
                )
            )

        return metadata_children

    def _build_dyld_load_command_children(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement]:
        """Build treemap elements for DYLD load command data (rebase, bind, export info, etc.)."""
        dyld_children: List[TreemapElement] = []

        dyld_info = binary_analysis.dyld_info
        if dyld_info is None:
            return dyld_children

        if dyld_info.chained_fixups_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Chained Fixups",
                    size=dyld_info.chained_fixups_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if dyld_info.export_trie_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Export Trie",
                    size=dyld_info.export_trie_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        return dyld_children

    def _get_element_type_from_tag(self, tag: BinaryTag) -> TreemapType:
        """Convert BinaryTag to TreemapType."""
        tag_value = tag.value
        if tag_value.startswith("dyld_"):
            return TreemapType.DYLD
        elif tag_value == "unmapped":
            return TreemapType.UNMAPPED
        elif tag_value == "code_signature":
            return TreemapType.CODE_SIGNATURE
        elif tag_value == "function_starts":
            return TreemapType.FUNCTION_STARTS
        elif tag_value == "external_methods":
            return TreemapType.EXTERNAL_METHODS
        else:
            return TreemapType.EXECUTABLES

    def _is_dyld_related(self, tag: BinaryTag, section_name: str) -> bool:
        """Check if a section is DYLD-related."""
        tag_value = tag.value
        return tag_value.startswith("dyld_") or section_name.startswith("LC_DYLD_") or "DYLD" in section_name.upper()

    def _categorize_section(self, section_name: str, segment_name: str) -> BinaryTag | None:
        """Categorize a section based on its name."""
        name_lower = section_name.lower()
        segment_name_lower = segment_name.lower()

        # Objective-C sections
        if "objc" in name_lower:
            return BinaryTag.OBJC_CLASSES

        # Swift metadata sections
        if "swift" in name_lower:
            return BinaryTag.SWIFT_METADATA

        # String sections
        if any(str_name in name_lower for str_name in ["__cstring", "__cfstring", "__ustring"]):
            return BinaryTag.C_STRINGS

        # GOT (Global Offset Table) and similar pointer sections
        if "__got" in name_lower or "__la_symbol_ptr" in name_lower or "__nl_symbol_ptr" in name_lower:
            return BinaryTag.DATA_SEGMENT

        # Const sections
        if "const" in name_lower:
            return BinaryTag.CONST_DATA

        # Unwind info
        if "unwind" in name_lower or "eh_frame" in name_lower:
            return BinaryTag.UNWIND_INFO

        # Text segment sections
        if (
            any(text_name in name_lower for text_name in ["__text", "__stubs", "__stub_helper"])
            or segment_name_lower == "__text"
        ):
            return BinaryTag.TEXT_SEGMENT

        # Data sections
        if (
            any(data_name in name_lower for data_name in ["__data", "__bss", "__common"])
            or segment_name_lower == "__data"
        ):
            return BinaryTag.DATA_SEGMENT

        return None
