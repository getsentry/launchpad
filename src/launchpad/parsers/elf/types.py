from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class SymbolSource(StrEnum):
    SEPARATE_DEBUG = "separate_debug"
    STATIC = "static_symbol_table"
    DYNAMIC = "dynamic_symbol_table"


class SizeQuality(StrEnum):
    EXACT = "exact"
    ESTIMATED = "estimated"
    AMBIGUOUS = "ambiguous"


class OwnershipQuality(StrEnum):
    VERIFIED_CLASS = "verified_class"
    INFERRED_CPP_SCOPE = "inferred_cpp_scope"
    NAMESPACE = "namespace"
    GLOBAL = "global"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ELFSection:
    index: int
    name: str
    section_type: str
    file_offset: int
    file_size: int
    virtual_address: int
    flags: int
    file_backed: bool


@dataclass(frozen=True)
class DwarfOwner:
    name: str
    quality: OwnershipQuality


@dataclass
class ELFSymbol:
    raw_name: str
    demangled_name: str | None
    symbol_type: str
    binding: str
    visibility: str
    section_index: int
    section_name: str
    virtual_address: int
    file_offset: int
    declared_size: int
    attributed_size: int
    source: SymbolSource
    size_quality: SizeQuality
    owner: str | None
    ownership_quality: OwnershipQuality
    special_kind: str | None = None
    aliases: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SectionRemainder:
    section_name: str
    size: int


@dataclass
class ELFParseResult:
    path: Path
    file_size: int
    elf_type: str
    architecture: str
    bitness: int
    endianness: str
    build_id: str | None
    debug_file: Path | None
    debug_source: SymbolSource
    sections: list[ELFSection]
    symbols: list[ELFSymbol]
    shared_size: int
    section_remainders: list[SectionRemainder]
    metadata_size: int
    warnings: list[str]

    @property
    def attributed_size(self) -> int:
        return sum(symbol.attributed_size for symbol in self.symbols)

    @property
    def exact_size(self) -> int:
        return sum(symbol.attributed_size for symbol in self.symbols if symbol.size_quality == SizeQuality.EXACT)

    @property
    def estimated_size(self) -> int:
        return sum(symbol.attributed_size for symbol in self.symbols if symbol.size_quality == SizeQuality.ESTIMATED)

    @property
    def unattributed_size(self) -> int:
        return self.metadata_size + sum(remainder.size for remainder in self.section_remainders)
