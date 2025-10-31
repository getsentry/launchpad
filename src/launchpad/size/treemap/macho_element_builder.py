from __future__ import annotations

from typing import Callable, Dict, List, TypedDict

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
            logger.warning(f"Size mismatch for {display_name}: file={file_info.size:,} treemap={total_child_size:,}")
            if diff > 0:
                logger.warning(f"  Difference: {abs(diff):,} bytes MISSING from treemap ({pct:.2f}%)")
            else:
                logger.warning(f"  Difference: {abs(diff):,} bytes OVER-COUNTED in treemap ({pct:.2f}%)")

    def _build_binary_treemap(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement] | None:
        binary_children: List[TreemapElement] = []

        # Section bookkeeping for remaining size
        section_remaining: Dict[str, int] = {}
        section_by_name: Dict[str, str] = {}  # section -> segment

        for seg in binary_analysis.segments:
            for sec in seg.sections or []:
                key = f"{seg.name}.{sec.name}"
                section_remaining[key] = sec.size
                section_by_name[sec.name] = seg.name

        def canonical_key(seg_name: str | None, sec_name: str | None) -> str | None:
            if not sec_name:
                return None
            seg = seg_name or section_by_name.get(sec_name)
            return f"{seg}.{sec_name}" if seg else None

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

        if binary_analysis.symbol_info:
            self._add_swift_symbols(
                binary_analysis.symbol_info, binary_children, section_subtractions, debit_section, canonical_key
            )
            self._add_objc_symbols(
                binary_analysis.symbol_info, binary_children, section_subtractions, debit_section, canonical_key
            )
            self._add_other_symbols(
                binary_analysis.symbol_info, binary_children, section_subtractions, debit_section, canonical_key
            )

        # Metadata
        binary_children.extend(self._build_metadata_components(binary_analysis))

        # Segments/sections (minus symbol bytes)
        self._add_segments(binary_analysis, binary_children, section_subtractions)

        # Unmapped region, if any remains
        self._add_unmapped_region(binary_analysis, binary_children)

        total_segments = sum(
            c.size
            for c in binary_children
            if c.type == TreemapType.EXECUTABLES
            and c.children is not None
            and any(
                ch.name.startswith("__")
                for ch in c.children  # crude: segments tend to have section children
            )
        )
        linkedit = next((c for c in binary_children if c.name == "__LINKEDIT"), None)
        header = next((c for c in binary_children if c.name == "Mach-O Header"), None)
        lcs = next((c for c in binary_children if c.name == "Load Commands"), None)
        total_accounted = sum(c.size for c in binary_children)

        logger.warning(
            "macho.treemap.accounting",
            extra={
                "total_segments": total_segments,
                "exec_size": binary_analysis.executable_size,
                "total_accounted": total_accounted,
                "__LINKEDIT_size": getattr(linkedit, "size", 0),
                "header_size": getattr(header, "size", 0),
                "load_cmds_size": getattr(lcs, "size", 0),
            },
        )

        return binary_children

    def _add_swift_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
        debit_section: DebitFn,
        canonical_key: CanonKeyFn,
    ) -> None:
        if not symbol_info.swift_type_groups:
            return

        swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
        for grp in symbol_info.swift_type_groups:
            swift_modules.setdefault(grp.module, []).append(grp)
            for sym in grp.symbols:
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

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
                comps = group.components
                if comps and comps[0] == module_name:
                    comps = comps[1:]
                comps = [c for c in comps if c and c[0].isupper()]
                if not comps:
                    continue

                cur = type_tree
                for i, comp in enumerate(comps):
                    node = _ensure(cur, comp)
                    if i == len(comps) - 1:
                        node["self_size"] += group.total_size
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
    ) -> None:
        if not symbol_info.objc_type_groups:
            return

        objc_classes: Dict[str, List[tuple[str, int]]] = {}
        for grp in symbol_info.objc_type_groups:
            objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", grp.total_size))
            for sym in grp.symbols:
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

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
    ) -> None:
        other_symbols_children: List[TreemapElement] = []
        total_other_symbols_size = 0

        # C++
        if symbol_info.cpp_type_groups:
            cpp_syms_with_size = []
            for grp in symbol_info.cpp_type_groups:
                for sym in grp.symbols:
                    if sym.size > 0:
                        cpp_syms_with_size.append(sym)
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    if taken:
                        key = canonical_key(sym.segment_name, sym.section_name)
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if cpp_syms_with_size:
                cpp_syms_with_size.sort(key=lambda s: s.size, reverse=True)
                cpp_size = sum(s.size for s in cpp_syms_with_size)
                total_other_symbols_size += cpp_size
                other_symbols_children.append(
                    TreemapElement(
                        name="C++",
                        size=cpp_size,
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
            comp_syms = [s for s in symbol_info.compiler_generated_symbols if s.size > 0]
            for sym in comp_syms:
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if comp_syms:
                comp_size = sum(s.size for s in comp_syms)
                total_other_symbols_size += comp_size
                other_symbols_children.append(
                    TreemapElement(
                        name="Compiler Generated",
                        size=comp_size,
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],  # Don't show the children because it can make diffs noisy
                    )
                )

        # C / other
        if symbol_info.other_symbols:
            other_syms = [s for s in symbol_info.other_symbols if s.size > 0]
            for sym in other_syms:
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if other_syms:
                other_syms.sort(key=lambda s: s.size, reverse=True)
                c_size = sum(s.size for s in other_syms)
                total_other_symbols_size += c_size
                other_symbols_children.append(
                    TreemapElement(
                        name="C Functions",
                        size=c_size,
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

    def _add_segments(
        self,
        binary_analysis: MachOBinaryAnalysis,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
    ) -> None:
        for segment in binary_analysis.segments:
            segment_name = segment.name
            segment_children: List[TreemapElement] = []

            if segment.sections:
                for section in segment.sections:
                    section_name = section.name
                    section_size = section.size
                    if section_size == 0:
                        continue

                    key = f"{segment_name}.{section_name}"
                    subtraction = section_subtractions.get(key, 0)
                    if subtraction > section_size:
                        logger.warning(
                            f"Section {key}: symbol bytes ({subtraction:,}) exceed section size ({section_size:,})."
                        )
                        subtraction = section_size

                    adjusted = section_size - subtraction
                    if adjusted <= 0:
                        continue

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

            linkedit_children_size = 0
            if segment_name == "__LINKEDIT":
                linkedit_children = self._build_linkedit_children(binary_analysis)
                segment_children.extend(linkedit_children)
                linkedit_children_size = sum(c.size for c in linkedit_children)

            displayed_section_size = sum(c.size for c in segment_children)

            seg_total_size = getattr(segment, "file_size", None)
            if not isinstance(seg_total_size, int) or seg_total_size <= 0:
                seg_total_size = segment.size

            total_section_declared = sum(s.size for s in segment.sections) if segment.sections else 0
            segment_overhead = seg_total_size - total_section_declared - linkedit_children_size
            actual_segment_size = displayed_section_size + max(0, segment_overhead)

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

    def _build_metadata_components(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement]:
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
            load_command_children: List[TreemapElement] = [
                TreemapElement(
                    name=lc.name,
                    size=lc.size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
                for lc in binary_analysis.load_commands
            ]
            metadata_children.append(
                TreemapElement(
                    name="Load Commands",
                    size=sum(lc.size for lc in binary_analysis.load_commands),
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=load_command_children,
                )
            )

        return metadata_children

    def _build_linkedit_children(self, binary_analysis: MachOBinaryAnalysis) -> List[TreemapElement]:
        """Build child elements for the __LINKEDIT segment.

        Includes symbol table, string table, function starts, DYLD info, and code signature.
        """
        linkedit_children: List[TreemapElement] = []

        le = binary_analysis.linkedit_info
        if le is None:
            return linkedit_children

        # Add symbol table and string table
        if le.string_table_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="String Table",
                    size=le.string_table_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if le.symbol_table_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="Symbol Table",
                    size=le.symbol_table_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if le.function_starts_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="Function Starts",
                    size=le.function_starts_size,
                    type=TreemapType.EXECUTABLES,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        # Add DYLD info
        if le.chained_fixups_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="Chained Fixups",
                    size=le.chained_fixups_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        if le.export_trie_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="Export Trie",
                    size=le.export_trie_size,
                    type=TreemapType.DYLD,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        # Add code signature
        if le.code_signature_size > 0:
            linkedit_children.append(
                TreemapElement(
                    name="Code Signature",
                    size=le.code_signature_size,
                    type=TreemapType.CODE_SIGNATURE,
                    path=None,
                    is_dir=False,
                    children=[],
                )
            )

        return linkedit_children

    def _add_unmapped_region(self, binary_analysis: MachOBinaryAnalysis, binary_children: List[TreemapElement]) -> None:
        total_accounted = sum(c.size for c in binary_children)
        if binary_analysis.executable_size > total_accounted:
            binary_children.append(
                TreemapElement(
                    name="Unmapped",
                    size=binary_analysis.executable_size - total_accounted,
                    type=TreemapType.UNMAPPED,
                    path=None,
                    is_dir=False,
                    children=[],
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
