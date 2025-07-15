from __future__ import annotations

from typing import Dict, List, TypedDict

from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeGroup
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.binary_component import BinaryComponent
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
        download_compression_ratio: float,
        filesystem_block_size: int,
        binary_analysis_map: Dict[str, MachOBinaryAnalysis],
    ) -> None:
        super().__init__(
            download_compression_ratio=download_compression_ratio,
            filesystem_block_size=filesystem_block_size,
        )
        self.binary_analysis_map = binary_analysis_map

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        """Entry-point: build a TreemapElement for one Mach-O."""
        if file_info.path not in self.binary_analysis_map:
            logger.warning("Binary %s found but not in binary analysis map", file_info.path)
            return None

        children = self._build_binary_treemap(
            name=display_name,
            file_path=file_info.path,
            binary_analysis=self.binary_analysis_map[file_info.path],
        )
        if children is None:
            return None

        return TreemapElement(
            name=display_name,
            install_size=file_info.size,
            download_size=file_info.size,
            element_type=TreemapType.EXECUTABLES,
            path=file_info.path,
            is_directory=False,
            children=children,
        )

    def _build_binary_treemap(
        self, *, name: str, file_path: str, binary_analysis: MachOBinaryAnalysis
    ) -> List[TreemapElement] | None:
        binary_component_analysis = binary_analysis.binary_analysis
        symbol_info = binary_analysis.symbol_info

        if binary_component_analysis is None:
            logger.warning("Binary %s has no component analysis", name)
            return None

        # ------------------------------------------------------------------ #
        # 1.  Group components by their descriptive name                     #
        # ------------------------------------------------------------------ #
        components_by_name: Dict[str, List[BinaryComponent]] = {}
        for component in binary_component_analysis.components:
            key = component.description or component.name
            components_by_name.setdefault(key, []).append(component)

        # Pre-compute component sizes grouped by name
        section_sizes: Dict[str, int] = {
            section_name: sum(c.size for c in components) for section_name, components in components_by_name.items()
        }

        #
        # These lists will accumulate children for the top-level element
        #
        section_children: List[TreemapElement] = []
        dyld_children: List[TreemapElement] = []
        symbol_children: List[TreemapElement] = []

        # Track how much of each section’s bytes we “burn” while assigning
        # bytes to symbols, so that we don’t double-count them later.
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
                        sec = str(sym.section.name)
                        section_subtractions[sec] = section_subtractions.get(sec, 0) + sym.size

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

                    # Drop segments that don’t look like type identifiers
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
                                install_size=node["self_size"],
                                download_size=node["self_size"],
                                element_type=TreemapType.MODULES,
                                path=None,
                                is_directory=False,
                                children=[],
                            )
                            child_elems.append(self_elem)
                            # after adding the pseudo-child, the parent’s size is just
                            # the sum of *all* children
                            total_size = sum(c.install_size for c in child_elems)
                        else:
                            # leaf, or container with no own bytes
                            total_size = node["self_size"] + sum(c.install_size for c in child_elems)

                        elems.append(
                            TreemapElement(
                                name=node["type_name"],
                                install_size=total_size,
                                download_size=total_size,
                                element_type=TreemapType.MODULES,
                                path=None,
                                is_directory=False,
                                children=child_elems,
                            )
                        )

                    return elems

                module_children = _tree_to_treemap(type_tree)
                module_total_size = sum(c.install_size for c in module_children)

                symbol_children.append(
                    TreemapElement(
                        name=module_name,
                        install_size=module_total_size,
                        download_size=module_total_size,
                        element_type=TreemapType.MODULES,
                        path=None,
                        is_directory=False,
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
                        sec = str(sym.section.name)
                        section_subtractions[sec] = section_subtractions.get(sec, 0) + sym.size

            for cls_name, meths in objc_classes.items():
                meth_elems: List[TreemapElement] = [
                    TreemapElement(
                        name=meth_name,
                        install_size=size,
                        download_size=size,
                        element_type=TreemapType.MODULES,
                        path=None,
                        is_directory=False,
                        children=[],
                    )
                    for meth_name, size in meths
                ]
                symbol_children.append(
                    TreemapElement(
                        name=cls_name,
                        install_size=sum(m.install_size for m in meth_elems),
                        download_size=sum(m.install_size for m in meth_elems),
                        element_type=TreemapType.MODULES,
                        path=None,
                        is_directory=True,
                        children=meth_elems,
                    )
                )

        # ------------------------------------------------------------------ #
        # 4.  Raw Mach-O components (minus whatever the symbols already took) #
        # ------------------------------------------------------------------ #
        for section_name, components in components_by_name.items():
            original = section_sizes.get(section_name, 0)
            adjusted = original - section_subtractions.get(section_name, 0)
            if adjusted <= 0:
                continue

            first_tag = components[0].tag.value
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

            elem = TreemapElement(
                name=section_name,
                install_size=adjusted,
                download_size=adjusted,
                element_type=element_type,
                path=None,
                is_directory=False,
                children=[],
                details={
                    "tag": first_tag,
                    "component_name": section_name,
                    "adjusted_size": adjusted,
                },
            )

            is_dyld = (
                first_tag.startswith("dyld_") or section_name.startswith("LC_DYLD_") or "DYLD" in section_name.upper()
            )
            (dyld_children if is_dyld else section_children).append(elem)

        # Bundle DYLD subsections under a synthetic parent
        if dyld_children:
            dyld_total = sum(c.install_size for c in dyld_children)
            section_children.append(
                TreemapElement(
                    name="DYLD",
                    install_size=dyld_total,
                    download_size=dyld_total,
                    element_type=TreemapType.DYLD,
                    path=None,
                    is_directory=True,
                    children=dyld_children,
                    details={"tag": "dyld"},
                )
            )

        # Add an explicit “Unmapped” region if present
        if binary_component_analysis.unanalyzed_size > 0:
            section_children.append(
                TreemapElement(
                    name="Unanalyzed",
                    install_size=int(binary_component_analysis.unanalyzed_size),
                    download_size=int(binary_component_analysis.unanalyzed_size),
                    element_type=TreemapType.UNMAPPED,
                    path=None,
                    is_directory=False,
                    children=[],
                )
            )

        # ------------------------------------------------------------------ #
        # 5.  Top-level element                                              #
        # ------------------------------------------------------------------ #
        return section_children + symbol_children
