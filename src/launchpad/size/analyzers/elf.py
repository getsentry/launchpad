from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from launchpad.artifacts.elf import ELFArtifact
from launchpad.parsers.elf.parser import ELFParser
from launchpad.parsers.elf.types import OwnershipQuality, SizeQuality
from launchpad.size.models.elf import (
    ELFAnalysisResults,
    ELFClassResult,
    ELFSectionResult,
    ELFSymbolResult,
)
from launchpad.size.treemap.elf_element_builder import ELFTreemapBuilder


class ELFAnalyzer:
    def __init__(self, debug_file: Path | None = None, **_: Any) -> None:
        self.debug_file = debug_file
        self._parser = ELFParser()
        self._treemap = ELFTreemapBuilder()

    def analyze(self, artifact: ELFArtifact) -> ELFAnalysisResults:
        parsed = self._parser.parse(artifact.path, self.debug_file)
        classes = self._classes(parsed.symbols)
        symbol_coverage = (parsed.attributed_size + parsed.shared_size) / parsed.file_size if parsed.file_size else 0.0
        owned_size = sum(symbol.attributed_size for symbol in parsed.symbols if symbol.owner is not None)
        ownership_coverage = owned_size / parsed.file_size if parsed.file_size else 0.0

        return ELFAnalysisResults(
            file_name=artifact.path.name,
            file_size=parsed.file_size,
            elf_type=parsed.elf_type,
            architecture=parsed.architecture,
            bitness=parsed.bitness,
            endianness=parsed.endianness,
            build_id=parsed.build_id,
            debug_file=str(parsed.debug_file) if parsed.debug_file else None,
            debug_source=parsed.debug_source,
            exact_size=parsed.exact_size,
            estimated_size=parsed.estimated_size,
            shared_size=parsed.shared_size,
            unattributed_size=parsed.unattributed_size,
            symbol_coverage=symbol_coverage,
            ownership_coverage=ownership_coverage,
            sections=[
                ELFSectionResult(
                    name=section.name,
                    section_type=section.section_type,
                    file_offset=section.file_offset,
                    file_size=section.file_size,
                    virtual_address=section.virtual_address,
                    file_backed=section.file_backed,
                )
                for section in parsed.sections
            ],
            classes=classes,
            symbols=[
                ELFSymbolResult(
                    raw_name=symbol.raw_name,
                    demangled_name=symbol.demangled_name,
                    symbol_type=symbol.symbol_type,
                    binding=symbol.binding,
                    visibility=symbol.visibility,
                    section_name=symbol.section_name,
                    virtual_address=symbol.virtual_address,
                    file_offset=symbol.file_offset,
                    declared_size=symbol.declared_size,
                    attributed_size=symbol.attributed_size,
                    source=symbol.source,
                    size_quality=symbol.size_quality,
                    owner=symbol.owner,
                    ownership_quality=symbol.ownership_quality,
                    special_kind=symbol.special_kind,
                    aliases=symbol.aliases,
                )
                for symbol in parsed.symbols
            ],
            warnings=parsed.warnings,
            treemap=self._treemap.build(parsed),
        )

    @staticmethod
    def _classes(symbols) -> list[ELFClassResult]:
        grouped = defaultdict(list)
        for symbol in symbols:
            if (
                symbol.attributed_size == 0
                or symbol.owner is None
                or symbol.ownership_quality
                not in {
                    OwnershipQuality.VERIFIED_CLASS,
                    OwnershipQuality.INFERRED_CPP_SCOPE,
                }
            ):
                continue
            grouped[(symbol.owner, symbol.ownership_quality)].append(symbol)

        classes = [
            ELFClassResult(
                name=name,
                ownership_quality=quality,
                size=sum(symbol.attributed_size for symbol in owner_symbols),
                exact_size=sum(
                    symbol.attributed_size for symbol in owner_symbols if symbol.size_quality == SizeQuality.EXACT
                ),
                estimated_size=sum(
                    symbol.attributed_size for symbol in owner_symbols if symbol.size_quality == SizeQuality.ESTIMATED
                ),
                symbol_count=len(owner_symbols),
            )
            for (name, quality), owner_symbols in grouped.items()
        ]
        classes.sort(key=lambda item: item.size, reverse=True)
        return classes
