from __future__ import annotations

from typing import Dict, List, TypedDict

from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeGroup
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.binary_component import BinaryTag
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
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

        logger.debug(f"Size validation for {display_name}:")
        logger.debug(f"  File size: {file_info.size:,} bytes")
        logger.debug(f"  Treemap total: {total_child_size:,} bytes")

        if size_diff > 0:
            logger.debug(f"  Difference: {size_diff_abs:,} bytes MISSING from treemap ({size_diff_percent:.2f}%)")
        elif size_diff < 0:
            logger.debug(f"  Difference: {size_diff_abs:,} bytes OVER-COUNTED in treemap ({size_diff_percent:.2f}%)")
        else:
            logger.debug("  Difference: 0 bytes - perfect match!")

    def _build_binary_treemap(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement] | None:
        symbol_info = binary_analysis.symbol_info
        segments = binary_analysis.segments

        binary_children: List[TreemapElement] = []

        # Track how much of each section's bytes we "burn" while assigning
        # bytes to symbols, so that we don't double-count them later.
        section_subtractions: Dict[str, int] = {}
        segment_subtractions: Dict[str, int] = {}

        # ------------------------------------------------------------------ #
        # 1.  Swift symbols -> nested module / type hierarchy                #
        # ------------------------------------------------------------------ #
        if symbol_info:
            # ---- 2a.  Bucket groups by Swift module ---------------------- #
            swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
            for grp in symbol_info.swift_type_groups:
                swift_modules.setdefault(grp.module, []).append(grp)

                # While we have the symbol handy, start tracking section usage
                for sym in grp.symbols:
                    if sym.section_name:
                        segment_name = sym.segment_name or "unknown"
                        # Use unique section name to avoid conflicts since the same section name can be used in multiple segments
                        unique_sec = f"{segment_name}.{sym.section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size
                        segment_subtractions[segment_name] = segment_subtractions.get(segment_name, 0) + sym.size

            # ---- 1b.  For every module build a nested tree --------------- #
            for module_name, type_groups in swift_modules.items():
                #
                # Build a forward tree where each node owns *only* the bytes
                # that belong to that concrete type (self_size).
                #
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

                #
                # Walk the finished tree bottom-up once to compute totals and
                # convert to TreemapElement objects.
                #
                def _tree_to_treemap(node_map: Dict[str, _SwiftTypeNode]) -> List[TreemapElement]:
                    elems: List[TreemapElement] = []

                    for node in node_map.values():
                        # recurse first
                        child_elems = _tree_to_treemap(node["children"])

                        # ------------------------------------------------------------------ #
                        # If this type has its own bytes *and* nested types, surface the     #
                        # bytes as a pseudo-child so the treemap can render them.            #
                        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # 2.  Objective-C symbols -> simple class / method hierarchy         #
        # ------------------------------------------------------------------ #
        if symbol_info:
            objc_classes: Dict[str, List[tuple[str, int]]] = {}
            for grp in symbol_info.objc_type_groups:
                objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", grp.total_size))
                for sym in grp.symbols:
                    if sym.section_name:
                        segment_name = sym.segment_name or "unknown"
                        # Use unique section name to avoid conflicts
                        unique_sec = f"{segment_name}.{sym.section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size
                        segment_subtractions[segment_name] = segment_subtractions.get(segment_name, 0) + sym.size

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

        # ------------------------------------------------------------------ #
        # 3.  Binary metadata components (headers, load commands, etc.)       #
        # ------------------------------------------------------------------ #
        metadata_children = self._build_metadata_components(binary_analysis)
        binary_children.extend(metadata_children)

        # ------------------------------------------------------------------ #
        # 4.  Raw segments/sections (minus whatever the symbols already took) #
        # ------------------------------------------------------------------ #
        for segment in segments:
            segment_name = segment.name
            segment_size = segment.size
            segment_children: List[TreemapElement] = []

            segment_symbol_bytes = segment_subtractions.get(segment_name, 0)

            if segment.sections:
                for section in segment.sections:
                    section_name = section.name
                    section_size = section.size

                    if section_size == 0:
                        logger.debug(f"Skipping section {section_name} with zero size")
                        continue

                    # Calculate adjusted section size after symbol subtraction
                    unique_sec = f"{segment_name}.{section_name}"
                    adjusted = section_size - section_subtractions.get(unique_sec, 0)
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

            actual_segment_size = segment_size - segment_symbol_bytes

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

        # Add an explicit "Unmapped" region if present (simplified - just check if we have unaccounted bytes)
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

        return binary_children

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
