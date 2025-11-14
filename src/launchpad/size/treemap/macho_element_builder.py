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

        # Collect debug info - only log if there's a mismatch
        debug_log: List[str] = []
        accounting_issues: List[str] = []  # Track specific bugs

        # Section bookkeeping for remaining size
        section_remaining: Dict[str, int] = {}
        section_by_name: Dict[str, str] = {}  # section -> segment
        section_original_size: Dict[str, int] = {}  # Track original sizes

        debug_log.append("=== Starting binary treemap build ===")
        debug_log.append(f"Total executable size: {binary_analysis.executable_size:,}")

        for seg in binary_analysis.segments:
            for sec in seg.sections or []:
                key = f"{seg.name}.{sec.name}"
                # Only track non-zerofill sections for file size accounting
                if not sec.is_zerofill:
                    section_remaining[key] = sec.size
                    section_original_size[key] = sec.size
                    section_by_name[sec.name] = seg.name

        # Count zero-fill sections for logging
        zerofill_sections = sum(
            1 for seg in binary_analysis.segments if seg.sections for sec in seg.sections if sec.is_zerofill
        )

        debug_log.append(
            f"Initial section inventory: {len(section_remaining)} sections (excluding {zerofill_sections} zero-fill sections)"
        )
        total_section_bytes = sum(section_remaining.values())
        debug_log.append(f"Total section bytes: {total_section_bytes:,}")

        # Track debit operations for summary logging
        debit_summary: Dict[str, int] = {}  # section_key -> total debited
        debit_count: Dict[str, int] = {}  # section_key -> number of operations

        def canonical_key(seg_name: str | None, sec_name: str | None) -> str | None:
            if not sec_name:
                return None
            seg = seg_name or section_by_name.get(sec_name)
            return f"{seg}.{sec_name}" if seg else None

        def debit_section(seg_name: str | None, sec_name: str | None, sz: int) -> int:
            if sz <= 0:
                return 0
            key = canonical_key(seg_name, sec_name)
            # If section not in section_remaining, it's likely a zero-fill section
            # Zero-fill sections don't occupy file space, so we don't debit from them
            if not key or key not in section_remaining:
                return 0
            take = min(sz, section_remaining[key])
            if take:
                section_remaining[key] -= take
                debit_summary[key] = debit_summary.get(key, 0) + take
                debit_count[key] = debit_count.get(key, 0) + 1
            return take

        section_subtractions: Dict[str, int] = {}

        if binary_analysis.symbol_info:
            debug_log.append("\n=== Processing Swift symbols ===")
            self._add_swift_symbols(
                binary_analysis.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                debug_log,
            )
            swift_size = sum(c.size for c in binary_children if c.type == TreemapType.MODULES)
            debug_log.append(f"Swift symbols total: {swift_size:,} bytes")
            debug_log.append(f"Section subtractions so far: {sum(section_subtractions.values()):,} bytes")

            debug_log.append("\n=== Processing ObjC symbols ===")
            objc_start = len(binary_children)
            self._add_objc_symbols(
                binary_analysis.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                debug_log,
            )
            objc_size = sum(c.size for c in binary_children[objc_start:] if c.type == TreemapType.MODULES)
            debug_log.append(f"ObjC symbols total: {objc_size:,} bytes")
            debug_log.append(f"Section subtractions so far: {sum(section_subtractions.values()):,} bytes")

            debug_log.append("\n=== Processing Other symbols ===")
            other_start = len(binary_children)
            self._add_other_symbols(
                binary_analysis.symbol_info,
                binary_children,
                section_subtractions,
                debit_section,
                canonical_key,
                debug_log,
            )
            other_size = sum(c.size for c in binary_children[other_start:])
            debug_log.append(f"Other symbols total: {other_size:,} bytes")
            debug_log.append(f"Section subtractions so far: {sum(section_subtractions.values()):,} bytes")

            # Check for accounting bugs after symbol processing
            total_symbols_size = sum(c.size for c in binary_children if c.type == TreemapType.MODULES)
            if total_symbols_size > binary_analysis.executable_size:
                accounting_issues.append(
                    f"BUG: Total symbol size ({total_symbols_size:,}) exceeds binary size ({binary_analysis.executable_size:,}) "
                    f"by {total_symbols_size - binary_analysis.executable_size:,} bytes"
                )

            # Check if we're claiming more bytes from sections than exist
            total_claimed = sum(section_subtractions.values())
            total_available = sum(section_original_size.values())
            if total_claimed > total_available:
                accounting_issues.append(
                    f"BUG: Total bytes claimed from sections ({total_claimed:,}) exceeds total section bytes ({total_available:,}) "
                    f"by {total_claimed - total_available:,} bytes - symbols are double-counting!"
                )

            # Check for individual symbol elements with suspicious sizes
            for elem in binary_children:
                if elem.type == TreemapType.MODULES:
                    if elem.size < 0:
                        accounting_issues.append(f"BUG: Symbol element '{elem.name}' has negative size: {elem.size:,}")
                    elif elem.size > binary_analysis.executable_size:
                        accounting_issues.append(
                            f"BUG: Symbol element '{elem.name}' size ({elem.size:,}) exceeds entire binary size ({binary_analysis.executable_size:,})"
                        )

        # Add debit summary and check for over-debiting
        if debit_summary:
            debug_log.append("\n=== Section Debit Summary ===")
            debug_log.append(f"Total sections debited: {len(debit_summary)}")
            for key in sorted(debit_summary.keys(), key=lambda k: debit_summary[k], reverse=True):
                original_size = section_original_size.get(key, 0)
                debited = debit_summary[key]
                remaining = section_remaining.get(key, 0)

                # Check for over-debiting bug
                if debited > original_size:
                    accounting_issues.append(
                        f"BUG: Section {key} over-debited: {debited:,} bytes claimed from {original_size:,} bytes "
                        f"(excess: {debited - original_size:,})"
                    )

                debug_log.append(
                    f"  {key}: {debited:,} bytes debited from {original_size:,} "
                    f"({debit_count[key]} operations, {remaining:,} remaining)"
                )

        # Metadata
        debug_log.append("\n=== Processing Metadata ===")
        metadata_start = len(binary_children)
        binary_children.extend(self._build_metadata_components(binary_analysis))
        metadata_size = sum(c.size for c in binary_children[metadata_start:])
        debug_log.append(f"Metadata total: {metadata_size:,} bytes (header + load commands)")

        # Segments/sections (minus symbol bytes)
        debug_log.append("\n=== Processing Segments ===")
        debug_log.append(f"Total section_subtractions to apply: {sum(section_subtractions.values()):,} bytes")
        segments_start = len(binary_children)
        self._add_segments(binary_analysis, binary_children, section_subtractions, debug_log, accounting_issues)
        segments_size = sum(c.size for c in binary_children[segments_start:] if c.type == TreemapType.EXECUTABLES)
        debug_log.append(f"Segments total: {segments_size:,} bytes (after subtracting symbols)")

        # Check for mismatch BEFORE adding unmapped region
        symbols_total = sum(c.size for c in binary_children if c.type == TreemapType.MODULES)
        segments_total = sum(
            c.size
            for c in binary_children
            if c.type == TreemapType.EXECUTABLES
            and c.children is not None
            and any(ch.name.startswith("__") for ch in c.children)
        )
        linkedit = next((c for c in binary_children if c.name == "__LINKEDIT"), None)
        header = next((c for c in binary_children if c.name == "Mach-O Header"), None)
        lcs = next((c for c in binary_children if c.name == "Load Commands"), None)
        total_accounted_before_unmapped = sum(c.size for c in binary_children)
        difference = total_accounted_before_unmapped - binary_analysis.executable_size

        # Only log debug details if there's a mismatch OR if we detected accounting bugs
        if difference != 0 or accounting_issues:
            debug_log.append("\n=== Final Accounting (BEFORE Unmapped adjustment) ===")
            debug_log.append(f"Executable size: {binary_analysis.executable_size:,}")
            debug_log.append(f"Total accounted: {total_accounted_before_unmapped:,}")
            debug_log.append(f"Difference: {difference:,} ({'OVER-COUNTED' if difference > 0 else 'UNDER-COUNTED'})")
            debug_log.append(f"Percentage: {abs(difference) / binary_analysis.executable_size * 100:.2f}%")
            debug_log.append("\nBreakdown:")
            debug_log.append(f"  Symbols (Swift/ObjC/Other): {symbols_total:,}")
            debug_log.append(f"  Segments (remaining sections): {segments_total:,}")
            debug_log.append(f"  __LINKEDIT: {getattr(linkedit, 'size', 0):,}")
            debug_log.append(f"  Mach-O Header: {getattr(header, 'size', 0):,}")
            debug_log.append(f"  Load Commands: {getattr(lcs, 'size', 0):,}")

            # Output all collected debug logs
            logger.warning("===========================================")
            if difference != 0:
                logger.warning("MISMATCH DETECTED - Debug trace:")
            else:
                logger.warning("ACCOUNTING ISSUES DETECTED:")
            logger.warning("===========================================")

            # Show accounting issues FIRST if any were found
            if accounting_issues:
                logger.warning("")
                logger.warning("*** ACCOUNTING BUGS DETECTED ***")
                logger.warning("")
                for issue in accounting_issues:
                    logger.warning(f"  {issue}")
                logger.warning("")
                logger.warning("Full debug trace below:")
                logger.warning("")

            for line in debug_log:
                logger.warning(line)
            logger.warning("===========================================")

        # Unmapped region - this is a workaround that masks the real issue
        # TODO: Remove this once we fix the accounting issues
        self._add_unmapped_region(binary_analysis, binary_children)

        unmapped = next((c for c in binary_children if c.name == "Unmapped"), None)
        total_accounted = sum(c.size for c in binary_children)

        logger.warning(
            "macho.treemap.accounting",
            extra={
                "total_segments": segments_total,
                "exec_size": binary_analysis.executable_size,
                "total_accounted": total_accounted,
                "total_before_unmapped": total_accounted_before_unmapped,
                "__LINKEDIT_size": getattr(linkedit, "size", 0),
                "header_size": getattr(header, "size", 0),
                "load_cmds_size": getattr(lcs, "size", 0),
                "symbols_total": symbols_total,
                "unmapped_size": getattr(unmapped, "size", 0),
                "difference_before_unmapped": difference,
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
        debug_log: List[str],
    ) -> None:
        if not symbol_info.swift_type_groups:
            return

        total_swift_symbols = 0
        total_swift_claimed = 0
        total_swift_skipped = 0
        skipped_groups = 0

        # Track actual debited size per group (not just requested size)
        group_actual_sizes: Dict[int, int] = {}  # id(group) -> actual_debited_size

        swift_modules: Dict[str, List[SwiftSymbolTypeGroup]] = {}
        for grp in symbol_info.swift_type_groups:
            swift_modules.setdefault(grp.module, []).append(grp)
            actual_size = 0
            for sym in grp.symbols:
                total_swift_symbols += 1
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                actual_size += taken
                total_swift_claimed += taken
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken
            group_actual_sizes[id(grp)] = actual_size

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
                # Use actual debited size, not requested size
                actual_size = group_actual_sizes.get(id(group), 0)
                if actual_size == 0:
                    continue  # Skip groups with no actual size

                comps = group.components
                if comps and comps[0] == module_name:
                    comps = comps[1:]
                comps = [c for c in comps if c and c[0].isupper()]

                # Handle symbols that couldn't be demangled or have no components
                if not comps:
                    total_swift_skipped += actual_size
                    skipped_groups += 1
                    comps = ["Unattributed"]

                cur = type_tree
                for i, comp in enumerate(comps):
                    node = _ensure(cur, comp)
                    if i == len(comps) - 1:
                        node["self_size"] += actual_size
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

        debug_log.append(f"Swift: {total_swift_symbols} symbols, {total_swift_claimed:,} bytes claimed from sections")
        if total_swift_skipped > 0:
            debug_log.append(
                f"  Note: {skipped_groups} Swift groups ({total_swift_skipped:,} bytes) shown as 'Unattributed' (couldn't demangle)"
            )

    def _add_objc_symbols(
        self,
        symbol_info: SymbolInfo,
        binary_children: List[TreemapElement],
        section_subtractions: Dict[str, int],
        debit_section: DebitFn,
        canonical_key: CanonKeyFn,
        debug_log: List[str],
    ) -> None:
        if not symbol_info.objc_type_groups:
            return

        total_objc_symbols = 0
        total_objc_claimed = 0

        objc_classes: Dict[str, List[tuple[str, int]]] = {}
        for grp in symbol_info.objc_type_groups:
            objc_classes.setdefault(grp.class_name, []).append((grp.method_name or "class", grp.total_size))
            for sym in grp.symbols:
                total_objc_symbols += 1
                taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                total_objc_claimed += taken
                if taken:
                    key = canonical_key(sym.segment_name, sym.section_name)
                    section_subtractions[key] = section_subtractions.get(key, 0) + taken

        debug_log.append(f"ObjC: {total_objc_symbols} symbols, {total_objc_claimed:,} bytes claimed from sections")

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
        debug_log: List[str],
    ) -> None:
        other_symbols_children: List[TreemapElement] = []
        total_other_symbols_size = 0

        total_cpp_symbols = 0
        total_cpp_claimed = 0
        total_compiler_symbols = 0
        total_compiler_claimed = 0
        total_c_symbols = 0
        total_c_claimed = 0

        # C++
        if symbol_info.cpp_type_groups:
            cpp_syms_with_size = []
            cpp_actual_size = 0  # Track actual debited size
            for grp in symbol_info.cpp_type_groups:
                for sym in grp.symbols:
                    total_cpp_symbols += 1
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    total_cpp_claimed += taken
                    if taken > 0:
                        cpp_syms_with_size.append(sym)
                        cpp_actual_size += taken
                        key = canonical_key(sym.segment_name, sym.section_name)
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if cpp_syms_with_size:
                cpp_syms_with_size.sort(key=lambda s: s.size, reverse=True)
                total_other_symbols_size += cpp_actual_size  # Use actual debited size
                other_symbols_children.append(
                    TreemapElement(
                        name="C++",
                        size=cpp_actual_size,  # Use actual debited size
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
            comp_actual_size = 0  # Track actual debited size
            for sym in symbol_info.compiler_generated_symbols:
                if sym.size > 0:
                    total_compiler_symbols += 1
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    total_compiler_claimed += taken
                    if taken > 0:
                        comp_syms.append(sym)
                        comp_actual_size += taken
                        key = canonical_key(sym.segment_name, sym.section_name)
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if comp_syms:
                total_other_symbols_size += comp_actual_size  # Use actual debited size
                other_symbols_children.append(
                    TreemapElement(
                        name="Compiler Generated",
                        size=comp_actual_size,  # Use actual debited size
                        type=TreemapType.MODULES,
                        path=None,
                        is_dir=False,
                        children=[],  # Don't show the children because it can make diffs noisy
                    )
                )

        # C / other
        if symbol_info.other_symbols:
            other_syms = []
            c_actual_size = 0  # Track actual debited size
            for sym in symbol_info.other_symbols:
                if sym.size > 0:
                    total_c_symbols += 1
                    taken = debit_section(sym.segment_name, sym.section_name, sym.size)
                    total_c_claimed += taken
                    if taken > 0:
                        other_syms.append(sym)
                        c_actual_size += taken
                        key = canonical_key(sym.segment_name, sym.section_name)
                        section_subtractions[key] = section_subtractions.get(key, 0) + taken

            if other_syms:
                other_syms.sort(key=lambda s: s.size, reverse=True)
                total_other_symbols_size += c_actual_size  # Use actual debited size
                other_symbols_children.append(
                    TreemapElement(
                        name="C Functions",
                        size=c_actual_size,  # Use actual debited size
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

        debug_log.append(f"C++: {total_cpp_symbols} symbols, {total_cpp_claimed:,} bytes claimed")
        debug_log.append(f"Compiler-gen: {total_compiler_symbols} symbols, {total_compiler_claimed:,} bytes claimed")
        debug_log.append(f"C/Other: {total_c_symbols} symbols, {total_c_claimed:,} bytes claimed")

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
        debug_log: List[str],
        accounting_issues: List[str],
    ) -> None:
        for segment in binary_analysis.segments:
            segment_name = segment.name
            segment_children: List[TreemapElement] = []

            debug_log.append(f"\nProcessing segment: {segment_name}")

            if segment.sections:
                for section in segment.sections:
                    section_name = section.name
                    section_size = section.size

                    # Skip zero-fill sections - they don't occupy file space
                    if section.is_zerofill:
                        debug_log.append(f"  Section {section_name}: SKIPPED (zero-fill section)")
                        continue

                    if section_size == 0:
                        continue

                    key = f"{segment_name}.{section_name}"
                    subtraction = section_subtractions.get(key, 0)

                    # Check for subtraction exceeding section size - this is a BUG
                    if subtraction > section_size:
                        accounting_issues.append(
                            f"BUG: Section {key} subtraction ({subtraction:,}) exceeds section size ({section_size:,}) "
                            f"by {subtraction - section_size:,} bytes"
                        )
                        logger.warning(
                            f"Section {key}: symbol bytes ({subtraction:,}) exceed section size ({section_size:,})."
                        )
                        subtraction = section_size

                    adjusted = section_size - subtraction

                    # Check for negative adjusted size
                    if adjusted < 0:
                        accounting_issues.append(
                            f"BUG: Section {key} has negative adjusted size: {adjusted:,} "
                            f"(size={section_size:,}, subtraction={subtraction:,})"
                        )

                    debug_log.append(
                        f"  Section {section_name}: size={section_size:,}, subtraction={subtraction:,}, adjusted={adjusted:,}"
                    )
                    if adjusted <= 0:
                        debug_log.append(f"  -> Skipping {section_name} (fully accounted for by symbols)")
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

                    # Check for negative size in treemap element
                    if elem.size < 0:
                        accounting_issues.append(
                            f"BUG: Created treemap element with negative size: {section_name} = {elem.size:,}"
                        )

                    segment_children.append(elem)

            linkedit_children_size = 0
            if segment_name == "__LINKEDIT":
                linkedit_children = self._build_linkedit_children(binary_analysis)
                segment_children.extend(linkedit_children)
                linkedit_children_size = sum(c.size for c in linkedit_children)

            displayed_section_size = sum(c.size for c in segment_children)

            seg_total_size = getattr(segment, "file_size", None)
            if not isinstance(seg_total_size, int) or seg_total_size <= 0:
                seg_total_size = segment.size

            # Only count non-zerofill sections toward file size
            total_section_declared = (
                sum(s.size for s in segment.sections if not s.is_zerofill) if segment.sections else 0
            )
            segment_overhead = seg_total_size - total_section_declared - linkedit_children_size
            actual_segment_size = displayed_section_size + max(0, segment_overhead)

            # Check for suspicious segment overhead
            if segment_overhead < 0:
                accounting_issues.append(
                    f"BUG: Segment {segment_name} has negative overhead: {segment_overhead:,} "
                    f"(file_size={seg_total_size:,}, sections={total_section_declared:,}, linkedit={linkedit_children_size:,})"
                )
            elif segment_overhead > seg_total_size * 0.1:  # More than 10% overhead is suspicious
                accounting_issues.append(
                    f"SUSPICIOUS: Segment {segment_name} has large overhead: {segment_overhead:,} "
                    f"({segment_overhead / seg_total_size * 100:.1f}% of segment size)"
                )

            # Check if actual segment size exceeds file size
            if actual_segment_size > seg_total_size:
                accounting_issues.append(
                    f"BUG: Segment {segment_name} actual size ({actual_segment_size:,}) exceeds file size ({seg_total_size:,}) "
                    f"by {actual_segment_size - seg_total_size:,} bytes"
                )

            debug_log.append(f"  Segment {segment_name} summary:")
            debug_log.append(f"    file_size: {seg_total_size:,}")
            debug_log.append(f"    total_section_declared: {total_section_declared:,}")
            debug_log.append(f"    displayed_section_size: {displayed_section_size:,}")
            debug_log.append(f"    linkedit_children_size: {linkedit_children_size:,}")
            debug_log.append(f"    segment_overhead: {segment_overhead:,}")
            debug_log.append(f"    actual_segment_size: {actual_segment_size:,}")

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
