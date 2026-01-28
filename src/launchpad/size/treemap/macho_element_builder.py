from __future__ import annotations

from typing import Callable, Dict, List, TypedDict

from launchpad.size.models.apple import ArchitectureSlice, LinkEditInfo, MachOBinaryAnalysis
from launchpad.size.models.binary_component import BinaryTag
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.symbols.partitioner import SymbolInfo
from launchpad.size.symbols.types import SwiftSymbolTypeGroup
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class _SwiftTypeNode(TypedDict):
    children: Dict[str, "_SwiftTypeNode"]
    self_size: int
    type_name: str


DebitFn = Callable[[str | None, str | None, int], int]
CanonKeyFn = Callable[[str | None, str | None], str | None]


class MachOElementBuilder(TreemapElementBuilder):
    def __init__(
        self,
        filesystem_block_size: int,
        binary_analysis_map: Dict[str, MachOBinaryAnalysis],
    ) -> None:
        super().__init__(filesystem_block_size=filesystem_block_size)
        self.binary_analysis_map = binary_analysis_map

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        if file_info.path not in self.binary_analysis_map:
            logger.warning("Binary %s found but not in binary analysis map", file_info.path)
            return None

        logger.debug(f"Building treemap for {display_name}")

        children = self._build_binary_treemap(self.binary_analysis_map[file_info.path])
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
        total_child_size = sum(e.size for e in children)
        diff = file_info.size - total_child_size
        if diff != 0:
            pct = (abs(diff) / file_info.size * 100) if file_info.size else 0
            logger.warning(
                "macho.treemap.size_mismatch",
                extra={
                    "binary_name": display_name,
                    "file_size": file_info.size,
                    "treemap_size": total_child_size,
                    "difference": abs(diff),
                    "difference_type": "missing" if diff > 0 else "over_counted",
                    "percentage": round(pct, 2),
                },
            )

    def _build_binary_treemap(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement] | None:
        slices = binary_analysis.architecture_slices
        if not slices:
            return None

        if len(slices) > 1:
            # Multiple architectures - wrap each in a parent node
            return [
                TreemapElement(
                    name=arch_slice.arch_name,
                    size=arch_slice.size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=self._build_arch_slice_treemap(arch_slice),
                )
                for arch_slice in slices
            ]

        # Single architecture - no wrapper node
        return self._build_arch_slice_treemap(slices[0])

    def _build_arch_slice_treemap(self, arch_slice: ArchitectureSlice) -> List[TreemapElement]:
        """Build treemap for a single architecture slice."""
        binary_children: List[TreemapElement] = []

        # Section bookkeeping for remaining size
        section_remaining: Dict[str, int] = {}
        zerofill_sections_set: set[str] = set()

        for seg in arch_slice.segments:
            for sec in seg.sections or []:
                key = f"{seg.name}.{sec.name}"
                if not sec.is_zerofill:
                    section_remaining[key] = sec.size
                else:
                    zerofill_sections_set.add(key)

        def canonical_key(seg_name: str | None, sec_name: str | None) -> str | None:
            if not sec_name or not seg_name:
                return None
            return f"{seg_name}.{sec_name}"

        def debit_section(seg_name: str | None, sec_name: str | None, sz: int) -> int:
            if sz <= 0:
                return 0
            key = canonical_key(seg_name, sec_name)
            if not key or key not in section_remaining:
                return 0
            take = min(sz, section_remaining[key])
            if take:
                section_remaining[key] -= take
            return take

        section_subtractions: Dict[str, int] = {}

        # Add symbols if this slice has symbol_info (only primary slice will have this)
        if arch_slice.symbol_info:
            self._add_swift_symbols(
                arch_slice.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                zerofill_sections_set,
            )

            self._add_objc_symbols(
                arch_slice.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                zerofill_sections_set,
            )

            self._add_other_symbols(
                arch_slice.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                zerofill_sections_set,
            )

        # Metadata
        binary_children.extend(self._build_arch_slice_metadata(arch_slice))

        # Segments/sections (minus symbol bytes)
        self._add_arch_slice_segments(arch_slice, binary_children, section_subtractions)

        # Add unmapped region
        self._add_arch_slice_unmapped(arch_slice, binary_children)

        return binary_children

    def _build_arch_slice_metadata(self, arch_slice: ArchitectureSlice) -> List[TreemapElement]:
        """Build metadata components for an architecture slice."""
        metadata_children: List[TreemapElement] = []

        if arch_slice.header_size > 0:
            metadata_children.append(
                TreemapElement(
                    name="Mach-O Header",
                    size=arch_slice.header_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if arch_slice.load_commands:
            load_command_children: List[TreemapElement] = [
                TreemapElement(
                    name=lc.name,
                    size=lc.size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
                for lc in arch_slice.load_commands
            ]
            metadata_children.append(
                TreemapElement(
                    name="Load Commands",
                    size=sum(lc.size for lc in arch_slice.load_commands),
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=load_command_children,
                )
            )

        return metadata_children

    def _add_arch_slice_segments(
        self,
        arch_slice: ArchitectureSlice,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        """Add segment elements for an architecture slice."""
        for segment in arch_slice.segments:
            segment_name = segment.name
            segment_children: List[TreemapElement] = []

            if segment.sections:
                for section in segment.sections:
                    section_name = section.name
                    section_size = section.size

                    if section.is_zerofill:
                        continue

                    if section_size == 0:
                        continue

                    key = f"{segment_name}.{section_name}"
                    subtraction = section_subtractions.get(key, 0)

                    if subtraction > section_size:
                        subtraction = section_size

                    adjusted = section_size - subtraction

                    if adjusted <= 0:
                        continue

                    tag = self._categorize_section(section_name, segment_name) or BinaryTag.OTHER
                    elem = TreemapElement(
                        name=section_name,
                        size=adjusted,
                        type=self._get_element_type_from_tag(tag),
                        path=None,
                        is_dir=False,
                        children=[],
                    )

                    segment_children.append(elem)

            linkedit_children_size = 0
            if segment_name == "__LINKEDIT" and arch_slice.linkedit_info:
                linkedit_children = self._build_linkedit_children_from_info(arch_slice.linkedit_info)
                segment_children.extend(linkedit_children)
                linkedit_children_size = sum(c.size for c in linkedit_children)

            seg_total_size = segment.size

            total_section_declared = (
                sum(s.size for s in segment.sections if not s.is_zerofill) if segment.sections else 0
            )
            segment_overhead = seg_total_size - total_section_declared - linkedit_children_size

            if segment_overhead > 0:
                segment_children.append(
                    TreemapElement(
                        name="Unmapped",
                        size=segment_overhead,
                        type=TreemapType.UNMAPPED,
                        path=None,
                        is_dir=False,
                        children=[],
                    )
                )

            actual_segment_size = sum(c.size for c in segment_children)

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

    def _build_linkedit_children_from_info(self, linkedit_info: LinkEditInfo) -> List[TreemapElement]:
        """Build __LINKEDIT children from LinkEditInfo."""
        linkedit_components = [
            ("Symbol Table", linkedit_info.symbol_table_size, TreemapType.EXECUTABLES),
            ("String Table", linkedit_info.string_table_size, TreemapType.STRINGS),
            ("Function Starts", linkedit_info.function_starts_size, TreemapType.EXECUTABLES),
            ("Chained Fixups", linkedit_info.chained_fixups_size, TreemapType.EXECUTABLES),
            ("Export Trie", linkedit_info.export_trie_size, TreemapType.EXECUTABLES),
            ("Code Signature", linkedit_info.code_signature_size, TreemapType.EXECUTABLES),
        ]

        return [
            TreemapElement(
                name=name,
                size=size,
                type=treemap_type,
                path=None,
                is_dir=False,
                children=[],
            )
            for name, size, treemap_type in linkedit_components
            if size > 0
        ]

    def _add_arch_slice_unmapped(self, arch_slice: ArchitectureSlice, binary_children: List[TreemapElement]) -> None:
        """Add unmapped region for architecture slice."""
        total_accounted = sum(c.size for c in binary_children)
        if arch_slice.size > total_accounted:
            binary_children.append(
                TreemapElement(
                    name="Unmapped",
                    size=arch_slice.size - total_accounted,
                    type=TreemapType.UNMAPPED,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

    def _add_swift_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
        debit_section: DebitFn,
        canonical_key: CanonKeyFn,
        zerofill_sections: set[str],
    ) -> None:
        if not symbol_info.swift_type_groups:
            return

        swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
        # Track the actual size of each group (excluding zerofill symbols)
        group_file_sizes: Dict[int, int] = {}

        for grp in symbol_info.swift_type_groups:
            swift_modules.setdefault(grp.module, []).append(grp)
            file_size = 0
            for sym in grp.symbols:
                # Skip symbols in zerofill sections - they don't occupy file space
                key = canonical_key(sym.segment_name, sym.section_name)
                if key and key in zerofill_sections:
                    continue

                file_size += sym.size
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken
                elif sym.size > 0:
                    # This is a bug - symbol has size but couldn't debit
                    logger.warning(
                        "macho.treemap.symbol_not_debited",
                        extra={
                            "symbol": sym.mangled_name,
                            "size": sym.size,
                            "section": key,
                        },
                    )
            group_file_sizes[id(grp)] = file_size

        def _ensure(node_map: Dict[str, _SwiftTypeNode], name: str) -> _SwiftTypeNode:
            if name not in node_map:
                node_map[name] = {"children": {}, "self_size": 0, "type_name": name}
            return node_map[name]

        def _tree_to_treemap(node_map: Dict[str, _SwiftTypeNode]) -> List[TreemapElement]:
            elems: List[TreemapElement] = []
            for node in node_map.values():
                child_elems = _tree_to_treemap(node["children"])
                if node["self_size"] > 0 and child_elems:
                    child_elems.append(
                        TreemapElement(
                            name=node["type_name"],
                            size=node["self_size"],
                            type=TreemapType.MODULES,
                            path=None,
                            is_dir=False,
                            children=[],
                        )
                    )
                    total_size = sum(c.size for c in child_elems)
                else:
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

        for module_name, type_groups in swift_modules.items():
            type_tree: Dict[str, _SwiftTypeNode] = {}

            for group in type_groups:
                file_size = group_file_sizes.get(id(group), 0)
                if file_size == 0:
                    continue

                comps = group.components
                if comps and comps[0] == module_name:
                    comps = comps[1:]
                comps = [c for c in comps if c and c[0].isupper()]

                # Handle symbols that couldn't be demangled or have no components
                if not comps:
                    comps = ["Unattributed"]

                cur = type_tree
                for i, comp in enumerate(comps):
                    node = _ensure(cur, comp)
                    if i == len(comps) - 1:
                        node["self_size"] += file_size
                    cur = node["children"]

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
        debit_section: DebitFn,
        canonical_key: CanonKeyFn,
        zerofill_sections: set[str],
    ) -> None:
        if not symbol_info.objc_type_groups:
            return

        objc_classes: Dict[str, List[tuple[str, int]]] = {}
        for grp in symbol_info.objc_type_groups:
            file_size = 0
            for sym in grp.symbols:
                key = canonical_key(sym.segment_name, sym.section_name)
                if key and key in zerofill_sections:
                    continue
                file_size += sym.size
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

            objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", file_size))

        for cls_name, meths in objc_classes.items():
            meth_elems = [
                TreemapElement(
                    name=meth,
                    size=size,
                    type=TreemapType.MODULES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
                for (meth, size) in meths
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
        debit_section: DebitFn,
        canonical_key: CanonKeyFn,
        zerofill_sections: set[str],
    ) -> None:
        other_symbols_children: List[TreemapElement] = []
        total_other_symbols_size = 0

        # C++
        if symbol_info.cpp_type_groups:
            cpp_syms_with_size = []
            for grp in symbol_info.cpp_type_groups:
                for sym in grp.symbols:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    if key and key in zerofill_sections:
                        continue
                    if sym.size > 0:
                        cpp_syms_with_size.append(sym)
                        taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                        if taken:
                            section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if cpp_syms_with_size:
                cpp_syms_with_size.sort(key=lambda s: s.size, reverse=True)
                cpp_total_size = sum(s.size for s in cpp_syms_with_size)
                total_other_symbols_size += cpp_total_size
                other_symbols_children.append(
                    TreemapElement(
                        name="C++",
                        size=cpp_total_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[
                            TreemapElement(
                                name=s.mangled_name,
                                size=s.size,
                                type=TreemapType.MODULES,
                                path=None,
                                is_dir=False,
                                children=[],
                            )
                            for s in cpp_syms_with_size[:50]
                        ],
                    )
                )

        # Compiler-generated
        if symbol_info.compiler_generated_symbols:
            comp_syms = []
            for sym in symbol_info.compiler_generated_symbols:
                key = canonical_key(sym.segment_name, sym.section_name)
                if key and key in zerofill_sections:
                    continue
                if sym.size > 0:
                    comp_syms.append(sym)
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    if taken:
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if comp_syms:
                comp_total_size = sum(s.size for s in comp_syms)
                total_other_symbols_size += comp_total_size
                other_symbols_children.append(
                    TreemapElement(
                        name="Compiler Generated",
                        size=comp_total_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],  # Don't show the children because it can make diffs noisy
                    )
                )

        # C / other
        if symbol_info.other_symbols:
            other_syms = []
            for sym in symbol_info.other_symbols:
                key = canonical_key(sym.segment_name, sym.section_name)
                if key and key in zerofill_sections:
                    continue
                if sym.size > 0:
                    other_syms.append(sym)
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    if taken:
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if other_syms:
                other_syms.sort(key=lambda s: s.size, reverse=True)
                c_total_size = sum(s.size for s in other_syms)
                total_other_symbols_size += c_total_size
                other_symbols_children.append(
                    TreemapElement(
                        name="C Functions",
                        size=c_total_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[
                            TreemapElement(
                                name=s.mangled_name,
                                size=s.size,
                                type=TreemapType.MODULES,
                                path=None,
                                is_dir=False,
                                children=[],
                            )
                            for s in other_syms[:50]
                        ],
                    )
                )

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

    def _get_element_type_from_tag(self, tag: BinaryTag) -> TreemapType:
        v = tag.value
        if v.startswith("dyld_"):
            return TreemapType.DYLD
        if v == "unmapped":
            return TreemapType.UNMAPPED
        if v == "code_signature":
            return TreemapType.CODE_SIGNATURE
        if v == "function_starts":
            return TreemapType.FUNCTION_STARTS
        if v == "external_methods":
            return TreemapType.EXTERNAL_METHODS
        return TreemapType.EXECUTABLES

    def _categorize_section(self, section_name: str, segment_name: str) -> BinaryTag | None:
        name_lower = section_name.lower()
        segment_name_lower = segment_name.lower()
        if "objc" in name_lower:
            return BinaryTag.OBJC_CLASSES
        if "swift" in name_lower:
            return BinaryTag.SWIFT_METADATA
        if any(s in name_lower for s in ["__cstring", "__cfstring", "__ustring"]):
            return BinaryTag.C_STRINGS
        if "__got" in name_lower or "__la_symbol_ptr" in name_lower or "__nl_symbol_ptr" in name_lower:
            return BinaryTag.DATA_SEGMENT
        if "const" in name_lower:
            return BinaryTag.CONST_DATA
        if "unwind" in name_lower or "eh_frame" in name_lower:
            return BinaryTag.UNWIND_INFO
        if any(t in name_lower for t in ["__text", "__stubs", "__stub_helper"]) or segment_name_lower == "__text":
            return BinaryTag.TEXT_SEGMENT
        if any(d in name_lower for d in ["__data", "__bss", "__common"]) or segment_name_lower == "__data":
            return BinaryTag.DATA_SEGMENT
        return None
