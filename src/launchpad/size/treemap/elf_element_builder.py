from __future__ import annotations

from collections import defaultdict

from launchpad.parsers.elf.types import ELFParseResult, ELFSymbol, OwnershipQuality
from launchpad.size.models.treemap import TreemapElement, TreemapResults, TreemapType

_CATEGORY_NAMES = {
    OwnershipQuality.VERIFIED_CLASS: "Verified classes",
    OwnershipQuality.INFERRED_CPP_SCOPE: "Inferred C++ scopes",
    OwnershipQuality.NAMESPACE: "Namespaces and free functions",
    OwnershipQuality.GLOBAL: "Global symbols",
    OwnershipQuality.UNKNOWN: "Unknown symbols",
}


class ELFTreemapBuilder:
    def build(self, result: ELFParseResult) -> TreemapResults:
        groups: dict[OwnershipQuality, dict[str, list[ELFSymbol]]] = defaultdict(lambda: defaultdict(list))
        for symbol in result.symbols:
            if symbol.attributed_size == 0:
                continue
            owner = symbol.owner or "(global)"
            groups[symbol.ownership_quality][owner].append(symbol)

        children: list[TreemapElement] = []
        for quality, category_name in _CATEGORY_NAMES.items():
            owners = groups.get(quality)
            if not owners:
                continue
            owner_nodes = [self._owner_node(owner, symbols) for owner, symbols in owners.items()]
            owner_nodes.sort(key=lambda node: node.size, reverse=True)
            children.append(
                TreemapElement(
                    name=category_name,
                    size=sum(node.size for node in owner_nodes),
                    type=TreemapType.CLASSES if quality == OwnershipQuality.VERIFIED_CLASS else TreemapType.SYMBOLS,
                    children=owner_nodes,
                )
            )

        if result.shared_size:
            children.append(
                TreemapElement(
                    name="Shared or ambiguous",
                    size=result.shared_size,
                    type=TreemapType.UNMAPPED,
                )
            )

        remainder_nodes = [
            TreemapElement(
                name=remainder.section_name,
                size=remainder.size,
                type=TreemapType.UNMAPPED,
            )
            for remainder in result.section_remainders
            if remainder.size
        ]
        if result.metadata_size:
            remainder_nodes.append(
                TreemapElement(name="ELF metadata and file gaps", size=result.metadata_size, type=TreemapType.BINARY)
            )
        if remainder_nodes:
            children.append(
                TreemapElement(
                    name="Unattributed",
                    size=sum(node.size for node in remainder_nodes),
                    type=TreemapType.UNMAPPED,
                    children=remainder_nodes,
                )
            )

        return TreemapResults(
            root=TreemapElement(
                name=result.path.name,
                size=result.file_size,
                type=TreemapType.BINARY,
                path=str(result.path),
                children=children,
            ),
            file_count=1,
            platform="elf",
        )

    @staticmethod
    def _owner_node(owner: str, symbols: list[ELFSymbol]) -> TreemapElement:
        symbol_nodes = [
            TreemapElement(
                name=symbol.demangled_name or symbol.raw_name,
                size=symbol.attributed_size,
                type=TreemapType.METHODS if symbol.symbol_type in {"func", "gnu_ifunc"} else TreemapType.SYMBOLS,
            )
            for symbol in symbols
        ]
        symbol_nodes.sort(key=lambda node: node.size, reverse=True)
        return TreemapElement(
            name=owner,
            size=sum(node.size for node in symbol_nodes),
            type=TreemapType.CLASSES,
            children=symbol_nodes,
        )
