from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

import lief

from launchpad.size.symbols.cpp_demangler import CppDemangler

from .debug_file import ELFDebugFileResolver
from .dwarf import DwarfOwnershipParser
from .types import (
    ELFParseResult,
    ELFSection,
    ELFSymbol,
    OwnershipQuality,
    SectionRemainder,
    SizeQuality,
    SymbolSource,
)

_SUPPORTED_TYPES = {"DYN", "EXEC"}
_SYMBOL_TYPES = {"FUNC", "GNU_IFUNC", "OBJECT", "TLS"}
_SPECIAL_PREFIXES = {
    "construction vtable for ": "construction_vtable",
    "covariant return thunk to ": "covariant_return_thunk",
    "guard variable for ": "guard_variable",
    "non-virtual thunk to ": "non_virtual_thunk",
    "typeinfo name for ": "typeinfo_name",
    "typeinfo for ": "typeinfo",
    "virtual thunk to ": "virtual_thunk",
    "vtable for ": "vtable",
    "VTT for ": "vtt",
}
_CLASS_OBJECT_KINDS = {"construction_vtable", "typeinfo", "typeinfo_name", "vtable", "vtt"}


@dataclass(frozen=True)
class _Candidate:
    symbol_index: int
    start: int
    end: int
    section_index: int
    quality: SizeQuality


class ELFParser:
    def __init__(self) -> None:
        self._debug_files = ELFDebugFileResolver()
        self._dwarf = DwarfOwnershipParser()
        self._demangler = CppDemangler()

    def parse(self, path: Path, debug_file: Path | None = None) -> ELFParseResult:
        binary = self._parse_binary(path)
        elf_type = binary.header.file_type.name
        if elf_type not in _SUPPORTED_TYPES:
            raise ValueError(f"Unsupported ELF type: {elf_type}")

        file_size = path.stat().st_size
        self._validate_layout(path, file_size)
        sections = self._sections(binary, file_size)
        resolved_debug = self._debug_files.resolve(path, debug_file)
        symbol_binary, source = self._symbol_binary(binary, resolved_debug)
        ownership_path = resolved_debug or path
        dwarf_owners = self._dwarf.parse(ownership_path)
        symbols, candidates = self._symbols(binary, symbol_binary, sections, source, dwarf_owners)
        shared_size, covered_by_section = self._attribute(symbols, candidates)
        remainders = [
            SectionRemainder(section.name, section.file_size - covered_by_section.get(section.index, 0))
            for section in sections
            if section.file_backed and section.file_size > covered_by_section.get(section.index, 0)
        ]
        section_bytes = sum(section.file_size for section in sections if section.file_backed)
        metadata_size = max(0, file_size - section_bytes)
        warnings = self._warnings(source, resolved_debug, dwarf_owners)

        return ELFParseResult(
            path=path,
            file_size=file_size,
            elf_type=elf_type,
            architecture=binary.header.machine_type.name.lower(),
            bitness=64 if binary.header.identity_class.name == "ELF64" else 32,
            endianness="little" if binary.header.identity_data.name == "LSB" else "big",
            build_id=self._debug_files.build_id(path),
            debug_file=resolved_debug,
            debug_source=source,
            sections=sections,
            symbols=symbols,
            shared_size=shared_size,
            section_remainders=remainders,
            metadata_size=metadata_size,
            warnings=warnings,
        )

    @staticmethod
    def _parse_binary(path: Path) -> lief.ELF.Binary:
        try:
            binary = lief.ELF.parse(path)
        except Exception as error:
            raise ValueError(f"Failed to parse ELF file: {path}") from error
        if binary is None:
            raise ValueError(f"Failed to parse ELF file: {path}")
        return binary

    @staticmethod
    def _validate_layout(path: Path, file_size: int) -> None:
        with path.open("rb") as stream:
            header = stream.read(64)
        elf_class = header[4] if len(header) > 4 else 0
        if elf_class == 2:
            minimum_size = 64
            program_offset = (32, 8)
            section_offset = (40, 8)
            header_size_offset = 52
            table_fields = ((54, 56, program_offset), (58, 60, section_offset))
        elif elf_class == 1:
            minimum_size = 52
            program_offset = (28, 4)
            section_offset = (32, 4)
            header_size_offset = 40
            table_fields = ((42, 44, program_offset), (46, 48, section_offset))
        else:
            raise ValueError(f"Failed to parse ELF file: {path}")
        if len(header) < minimum_size:
            raise ValueError(f"Failed to parse ELF file: {path}")

        byteorder = "little" if header[5] == 1 else "big"
        declared_header_size = int.from_bytes(header[header_size_offset : header_size_offset + 2], byteorder)
        if declared_header_size < minimum_size or declared_header_size > file_size:
            raise ValueError(f"Failed to parse ELF file: {path}")

        for entry_size_offset, count_offset, (offset_position, offset_size) in table_fields:
            offset = int.from_bytes(header[offset_position : offset_position + offset_size], byteorder)
            entry_size = int.from_bytes(header[entry_size_offset : entry_size_offset + 2], byteorder)
            count = int.from_bytes(header[count_offset : count_offset + 2], byteorder)
            if offset > file_size or (
                count and (offset == 0 or entry_size == 0 or offset + count * entry_size > file_size)
            ):
                raise ValueError(f"Failed to parse ELF file: {path}")

    @staticmethod
    def _sections(binary: lief.ELF.Binary, file_size: int) -> list[ELFSection]:
        sections: list[ELFSection] = []
        for index, section in enumerate(binary.sections):
            section_type = section.type.name
            offset = int(section.offset)
            size = int(section.size)
            file_backed = (
                section_type != "NOBITS" and size > 0 and 0 <= offset <= file_size and offset + size <= file_size
            )
            sections.append(
                ELFSection(
                    index=index,
                    name=str(section.name) or f"section_{index}",
                    section_type=section_type.lower(),
                    file_offset=offset,
                    file_size=size if file_backed else 0,
                    virtual_address=int(section.virtual_address),
                    flags=int(section.flags),
                    file_backed=file_backed,
                )
            )

        previous_end = 0
        for section in sorted(
            (section for section in sections if section.file_backed), key=lambda item: item.file_offset
        ):
            if section.file_offset < previous_end:
                raise ValueError(f"ELF section {section.name} overlaps another file-backed section")
            previous_end = section.file_offset + section.file_size
        return sections

    def _symbol_binary(self, binary: lief.ELF.Binary, debug_file: Path | None) -> tuple[lief.ELF.Binary, SymbolSource]:
        if debug_file is not None:
            debug_binary = self._parse_binary(debug_file)
            if any(symbol.name for symbol in debug_binary.symtab_symbols):
                return debug_binary, SymbolSource.SEPARATE_DEBUG
        if any(symbol.name for symbol in binary.symtab_symbols):
            return binary, SymbolSource.STATIC
        return binary, SymbolSource.DYNAMIC

    def _symbols(
        self,
        primary: lief.ELF.Binary,
        source_binary: lief.ELF.Binary,
        sections: list[ELFSection],
        source: SymbolSource,
        dwarf_owners: dict,
    ) -> tuple[list[ELFSymbol], list[_Candidate]]:
        source_sections = list(source_binary.sections)
        primary_sections_by_name = {section.name: section for section in sections}
        source_symbols = (
            source_binary.dynamic_symbols if source == SymbolSource.DYNAMIC else source_binary.symtab_symbols
        )
        symbols: list[ELFSymbol] = []
        raw_candidates: list[tuple[int, int, int, int]] = []
        verified_classes = {
            item.name for item in dwarf_owners.values() if item.quality == OwnershipQuality.VERIFIED_CLASS
        }

        for source_symbol in source_symbols:
            if not source_symbol.name or source_symbol.type.name not in _SYMBOL_TYPES:
                continue
            section_index = int(source_symbol.shndx)
            if section_index <= 0 or section_index >= len(source_sections):
                continue
            source_section = source_sections[section_index]
            section = primary_sections_by_name.get(str(source_section.name))
            if section is None or not section.file_backed:
                continue
            value = int(source_symbol.value)
            if primary.header.machine_type.name == "ARM" and source_symbol.type.name in {"FUNC", "GNU_IFUNC"}:
                value &= ~1
            relative_offset = value - int(source_section.virtual_address)
            file_offset = section.file_offset + relative_offset
            if file_offset < section.file_offset or file_offset >= section.file_offset + section.file_size:
                continue

            raw_name = str(source_symbol.name)
            demangled = self._demangler.demangle(raw_name)
            owner, ownership_quality, special_kind = self._ownership(
                raw_name, demangled, dwarf_owners, verified_classes
            )
            symbol = ELFSymbol(
                raw_name=raw_name,
                demangled_name=demangled,
                symbol_type=source_symbol.type.name.lower(),
                binding=source_symbol.binding.name.lower(),
                visibility=source_symbol.visibility.name.lower(),
                section_index=section.index,
                section_name=section.name,
                virtual_address=value,
                file_offset=file_offset,
                declared_size=int(source_symbol.size),
                attributed_size=0,
                source=source,
                size_quality=SizeQuality.EXACT,
                owner=owner,
                ownership_quality=ownership_quality,
                special_kind=special_kind,
            )
            symbol_index = len(symbols)
            symbols.append(symbol)
            raw_candidates.append((symbol_index, section.index, file_offset, int(source_symbol.size)))

        candidates = self._candidate_ranges(symbols, raw_candidates, sections)
        return symbols, candidates

    @staticmethod
    def _candidate_ranges(
        symbols: list[ELFSymbol],
        raw_candidates: list[tuple[int, int, int, int]],
        sections: list[ELFSection],
    ) -> list[_Candidate]:
        section_map = {section.index: section for section in sections}
        offsets_by_section: dict[int, list[int]] = {}
        for _, section_index, offset, _ in raw_candidates:
            offsets_by_section.setdefault(section_index, []).append(offset)
        for offsets in offsets_by_section.values():
            offsets[:] = sorted(set(offsets))

        candidates: list[_Candidate] = []
        for symbol_index, section_index, start, declared_size in raw_candidates:
            section = section_map[section_index]
            section_end = section.file_offset + section.file_size
            quality = SizeQuality.EXACT
            if declared_size > 0:
                end = min(start + declared_size, section_end)
                if end - start != declared_size:
                    quality = SizeQuality.ESTIMATED
            else:
                offsets = offsets_by_section[section_index]
                next_index = bisect_right(offsets, start)
                end = offsets[next_index] if next_index < len(offsets) else start
                quality = SizeQuality.ESTIMATED
            if end <= start:
                continue
            symbols[symbol_index].size_quality = quality
            candidates.append(_Candidate(symbol_index, start, end, section_index, quality))
        return candidates

    @staticmethod
    def _attribute(symbols: list[ELFSymbol], candidates: list[_Candidate]) -> tuple[int, dict[int, int]]:
        shared_size = 0
        covered_by_section: dict[int, int] = {}
        candidates_by_section: dict[int, list[_Candidate]] = {}
        alias_sets: dict[int, set[str]] = {}
        for candidate in candidates:
            candidates_by_section.setdefault(candidate.section_index, []).append(candidate)

        for section_index, section_candidates in candidates_by_section.items():
            starts: dict[int, list[int]] = {}
            ends: dict[int, list[int]] = {}
            for index, candidate in enumerate(section_candidates):
                starts.setdefault(candidate.start, []).append(index)
                ends.setdefault(candidate.end, []).append(index)

            active: set[int] = set()
            covered = 0
            previous: int | None = None
            for position in sorted(starts.keys() | ends.keys()):
                if previous is not None and position > previous and active:
                    size = position - previous
                    covered += size
                    owner_keys = {
                        (
                            symbols[section_candidates[index].symbol_index].owner
                            or symbols[section_candidates[index].symbol_index].raw_name,
                            symbols[section_candidates[index].symbol_index].ownership_quality,
                        )
                        for index in active
                    }
                    if len(owner_keys) != 1:
                        shared_size += size
                    else:
                        representative_index = min(
                            active,
                            key=lambda index: symbols[section_candidates[index].symbol_index].raw_name,
                        )
                        representative = section_candidates[representative_index]
                        target = symbols[representative.symbol_index]
                        target.attributed_size += size
                        if any(section_candidates[index].quality == SizeQuality.ESTIMATED for index in active):
                            target.size_quality = SizeQuality.ESTIMATED
                        aliases = alias_sets.setdefault(representative.symbol_index, set())
                        aliases.update(
                            symbols[section_candidates[index].symbol_index].raw_name
                            for index in active
                            if index != representative_index
                        )

                active.difference_update(ends.get(position, ()))
                active.update(starts.get(position, ()))
                previous = position
            covered_by_section[section_index] = covered

        for symbol_index, aliases in alias_sets.items():
            symbols[symbol_index].aliases = sorted(aliases)
        return shared_size, covered_by_section

    @staticmethod
    def _ownership(
        raw_name: str,
        demangled: str | None,
        dwarf_owners: dict,
        verified_classes: set[str],
    ) -> tuple[str | None, OwnershipQuality, str | None]:
        dwarf_owner = dwarf_owners.get(raw_name)
        if dwarf_owner is not None:
            special_kind = ELFParser._special_kind(demangled)
            return dwarf_owner.name, dwarf_owner.quality, special_kind
        if demangled is None:
            return None, OwnershipQuality.GLOBAL, None

        special_kind = ELFParser._special_kind(demangled)
        target = demangled
        for prefix in _SPECIAL_PREFIXES:
            if target.startswith(prefix):
                target = target[len(prefix) :]
                break
        callable_name = target.split("(", 1)[0]
        if special_kind in _CLASS_OBJECT_KINDS:
            owner = callable_name
        elif "::" in callable_name:
            owner = callable_name.rsplit("::", 1)[0]
        else:
            return None, OwnershipQuality.GLOBAL, special_kind

        quality = OwnershipQuality.VERIFIED_CLASS if owner in verified_classes else OwnershipQuality.INFERRED_CPP_SCOPE
        return owner, quality, special_kind

    @staticmethod
    def _special_kind(demangled: str | None) -> str | None:
        if demangled is None:
            return None
        return next((kind for prefix, kind in _SPECIAL_PREFIXES.items() if demangled.startswith(prefix)), None)

    @staticmethod
    def _warnings(source: SymbolSource, debug_file: Path | None, dwarf_owners: dict) -> list[str]:
        warnings: list[str] = []
        if source == SymbolSource.DYNAMIC:
            warnings.append("Static symbols are unavailable; analysis uses the dynamic symbol table")
        if debug_file is None and not dwarf_owners:
            warnings.append("DWARF data is unavailable; C++ ownership is inferred from demangled names")
        return warnings
