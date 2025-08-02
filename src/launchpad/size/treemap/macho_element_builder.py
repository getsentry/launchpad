from __future__ import annotations

from dataclasses import dataclass
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


@dataclass
class SegmentSection:
    """Represents a section within a segment."""

    segment_name: str
    section_name: str
    size: int
    tag: BinaryTag

    @property
    def unique_name(self) -> str:
        """Get unique name for treemap: segment.section"""
        return f"{self.segment_name}.{self.section_name}"


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
            name=display_name,
            binary_analysis=self.binary_analysis_map[file_info.path],
        )
        if children is None:
            return None

        # Verify that child sizes sum up to the total file size
        def _calculate_total_size(elements: List[TreemapElement]) -> int:
            """Recursively calculate the total size of treemap elements."""
            total = 0
            for element in elements:
                total += element.size
            return total

        total_child_size = _calculate_total_size(children)
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

        return TreemapElement(
            name=display_name,
            size=file_info.size,
            type=TreemapType.EXECUTABLES,
            path=file_info.path,
            is_dir=False,
            children=children,
        )

    def _build_binary_treemap(self, *, name: str, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement] | None:
        symbol_info = binary_analysis.symbol_info

        # ------------------------------------------------------------------ #
        # 1.  Extract segments and sections from available data              #
        # ------------------------------------------------------------------ #
        # Use the sections data and load commands from MachOBinaryAnalysis
        segment_sections = self._extract_segment_sections_from_analysis(binary_analysis)
        logger.debug(f"Extracted {len(segment_sections)} segment/sections from {name}")

        # Group sections by segment for treemap structure
        sections_by_segment: Dict[str, List[SegmentSection]] = {}
        for seg_sec in segment_sections:
            sections_by_segment.setdefault(seg_sec.segment_name, []).append(seg_sec)

        logger.debug(f"Grouped into {len(sections_by_segment)} segments: {list(sections_by_segment.keys())}")

        #
        # These lists will accumulate children for the top-level element
        #
        section_children: List[TreemapElement] = []
        symbol_children: List[TreemapElement] = []

        # Track how much of each section's bytes we "burn" while assigning
        # bytes to symbols, so that we don't double-count them later.
        # Use unique section names (segment.section) to avoid conflicts
        section_subtractions: Dict[str, int] = {}

        # ------------------------------------------------------------------ #
        # 2.  Swift symbols -> nested module / type hierarchy                #
        # ------------------------------------------------------------------ #
        if symbol_info:
            # ---- 2a.  Bucket groups by Swift module ---------------------- #
            swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
            for grp in symbol_info.swift_type_groups:
                swift_modules.setdefault(grp.module, []).append(grp)

                # While we have the symbol handy, start tracking section usage
                for sym in grp.symbols:
                    if sym.section:
                        # Use unique section name to avoid conflicts
                        segment_name = str(sym.section.segment.name) if sym.section.segment else "unknown"
                        section_name = str(sym.section.name)
                        unique_sec = f"{segment_name}.{section_name}"
                        section_subtractions[unique_sec] = section_subtractions.get(unique_sec, 0) + sym.size

            # ---- 2b.  For every module build a nested tree --------------- #
            for module_name, type_groups in swift_modules.items():
                #
                # Build a forward tree where each node owns *only* the bytes
                # that belong to that concrete type (self_size).  Children are
                # stored in a dict for fast look-ups as we stream the groups.
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

                symbol_children.append(
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
        # 3.  Objective-C symbols -> simple class / method hierarchy         #
        # ------------------------------------------------------------------ #
        if symbol_info:
            objc_classes: Dict[str, List[tuple[str, int]]] = {}
            for grp in symbol_info.objc_type_groups:
                objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", grp.total_size))
                for sym in grp.symbols:
                    if sym.section:
                        # Use unique section name to avoid conflicts
                        segment_name = str(sym.section.segment.name) if sym.section.segment else "unknown"
                        section_name = str(sym.section.name)
                        unique_sec = f"{segment_name}.{section_name}"
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
                symbol_children.append(
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
        # 4.  Binary metadata components (headers, load commands, etc.)       #
        # ------------------------------------------------------------------ #
        metadata_children = self._build_metadata_components(binary_analysis)
        section_children.extend(metadata_children)

        # ------------------------------------------------------------------ #
        # 5.  Raw segments/sections (minus whatever the symbols already took) #
        # ------------------------------------------------------------------ #
        for segment_name, seg_sections in sections_by_segment.items():
            segment_children: List[TreemapElement] = []
            linkedit_dyld_children: List[TreemapElement] = []

            for seg_sec in seg_sections:
                original = seg_sec.size
                adjusted = original - section_subtractions.get(seg_sec.unique_name, 0)
                logger.debug(
                    f"Section {seg_sec.unique_name}: original={original}, subtracted={section_subtractions.get(seg_sec.unique_name, 0)}, adjusted={adjusted}"
                )
                if adjusted <= 0:
                    logger.debug(f"Skipping section {seg_sec.unique_name} - no remaining size after symbol subtraction")
                    continue

                element_type = self._get_element_type_from_tag(seg_sec.tag)

                elem = TreemapElement(
                    name=seg_sec.section_name,
                    size=adjusted,
                    type=element_type,
                    path=None,
                    is_dir=False,
                    children=[],
                )

                is_dyld = self._is_dyld_related(seg_sec.tag, seg_sec.section_name)
                logger.debug(f"Section {seg_sec.section_name} is_dyld={is_dyld}, tag={seg_sec.tag.value}")
                segment_children.append(elem)

            # Special handling for LINKEDIT segment to include DYLD children
            if segment_name == "__LINKEDIT":
                # Add DYLD load command data as additional children of LINKEDIT
                linkedit_dyld_children.extend(self._build_dyld_load_command_children(binary_analysis))

                # Combine regular sections with DYLD children
                all_linkedit_children = segment_children + linkedit_dyld_children

                if all_linkedit_children:
                    segment_total = sum(c.size for c in all_linkedit_children)
                    logger.debug(
                        f"Adding LINKEDIT segment with {len(segment_children)} regular sections and {len(linkedit_dyld_children)} DYLD children, total size={segment_total}"
                    )
                    section_children.append(
                        TreemapElement(
                            name=segment_name,
                            size=segment_total,
                            type=TreemapType.EXECUTABLES,
                            path=None,
                            is_dir=False,
                            children=all_linkedit_children,
                        )
                    )
                else:
                    logger.debug("LINKEDIT segment has no children, skipping")
            else:
                # Add segment as parent if it has non-DYLD children
                if segment_children:
                    segment_total = sum(c.size for c in segment_children)
                    logger.debug(
                        f"Adding segment '{segment_name}' with {len(segment_children)} children, total size={segment_total}"
                    )
                    section_children.append(
                        TreemapElement(
                            name=segment_name,
                            size=segment_total,
                            type=TreemapType.EXECUTABLES,
                            path=None,
                            is_dir=False,
                            children=segment_children,
                        )
                    )
                else:
                    logger.debug(f"Segment '{segment_name}' has no non-DYLD children, skipping")

        # Add an explicit "Unmapped" region if present (simplified - just check if we have unaccounted bytes)
        total_accounted = sum(c.size for c in section_children + symbol_children)
        if binary_analysis.executable_size > total_accounted:
            unaccounted = binary_analysis.executable_size - total_accounted
            section_children.append(
                TreemapElement(
                    name="Unmapped",
                    size=unaccounted,
                    type=TreemapType.UNMAPPED,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        # ------------------------------------------------------------------ #
        # 6.  Top-level element                                              #
        # ------------------------------------------------------------------ #
        return section_children + symbol_children

    def _extract_segment_sections_from_analysis(self, binary_analysis: MachOBinaryAnalysis) -> List[SegmentSection]:
        """Extract segments and sections from MachOBinaryAnalysis data."""
        segment_sections: List[SegmentSection] = []

        segments = binary_analysis.segments
        logger.debug(f"Found {len(segments)} segments in stable data")

        for segment in segments:
            segment_name = segment.name
            logger.debug(f"Processing segment: '{segment_name}' with {len(segment.sections)} sections")

            if len(segment.sections) == 0:
                tag = self._categorize_section("", segment_name) or BinaryTag.OTHER
                segment_sections.append(
                    SegmentSection(segment_name=segment_name, section_name="", size=segment.size, tag=tag)
                )
                continue

            for section in segment.sections:
                section_name = section.name
                section_size = section.size

                logger.debug(f"Processing section '{section_name}' with size {section_size}")
                if section_size == 0:
                    logger.debug(f"Skipping section {section_name} with zero size")
                    continue

                tag = self._categorize_section(section_name, segment_name) or BinaryTag.OTHER
                logger.debug(f"Section '{section_name}' in '{segment_name}' (size: {section_size}) -> {tag.value}")
                segment_sections.append(
                    SegmentSection(segment_name=segment_name, section_name=section_name, size=section_size, tag=tag)
                )

        logger.debug(f"Returning {len(segment_sections)} segment sections")
        return segment_sections

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

        logger.debug(f"Added {len(metadata_children)} metadata components")
        return metadata_children

    def _build_dyld_load_command_children(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement]:
        """Build treemap elements for DYLD load command data (rebase, bind, export info, etc.)."""
        dyld_children: List[TreemapElement] = []

        logger.debug(f"Building DYLD children, dyld_info is None: {binary_analysis.dyld_info is None}")
        if binary_analysis.dyld_info is None:
            logger.debug("No DYLD info available in binary analysis")
            return dyld_children

        dyld_info = binary_analysis.dyld_info
        logger.debug(
            f"DYLD info sizes: rebase={dyld_info.rebase_size}, bind={dyld_info.bind_size}, weak_bind={dyld_info.weak_bind_size}, lazy_bind={dyld_info.lazy_bind_size}, export={dyld_info.export_size}"
        )

        if dyld_info.rebase_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Rebase Info",
                    size=dyld_info.rebase_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if dyld_info.bind_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Bind Info",
                    size=dyld_info.bind_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if dyld_info.weak_bind_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Weak Bind Info",
                    size=dyld_info.weak_bind_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if dyld_info.lazy_bind_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Lazy Bind Info",
                    size=dyld_info.lazy_bind_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if dyld_info.export_size > 0:
            dyld_children.append(
                TreemapElement(
                    name="Exports Trie",
                    size=dyld_info.export_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

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

        logger.debug(f"Built {len(dyld_children)} DYLD load command children")
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
