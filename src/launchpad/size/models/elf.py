from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from launchpad.parsers.elf.types import OwnershipQuality, SizeQuality, SymbolSource

from .treemap import TreemapResults

ELF_ANALYSIS_VERSION = "1.0.0"


class ELFSectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    section_type: str
    file_offset: int = Field(ge=0)
    file_size: int = Field(ge=0)
    virtual_address: int = Field(ge=0)
    file_backed: bool


class ELFSymbolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_name: str
    demangled_name: str | None
    symbol_type: str
    binding: str
    visibility: str
    section_name: str
    virtual_address: int = Field(ge=0)
    file_offset: int = Field(ge=0)
    declared_size: int = Field(ge=0)
    attributed_size: int = Field(ge=0)
    source: SymbolSource
    size_quality: SizeQuality
    owner: str | None
    ownership_quality: OwnershipQuality
    special_kind: str | None
    aliases: list[str] = Field(default_factory=list)


class ELFClassResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    ownership_quality: OwnershipQuality
    size: int = Field(ge=0)
    exact_size: int = Field(ge=0)
    estimated_size: int = Field(ge=0)
    symbol_count: int = Field(ge=0)


class ELFAnalysisResults(BaseModel):
    model_config = ConfigDict(frozen=True)

    generated_at: datetime = Field(default_factory=datetime.now)
    analysis_duration: float | None = Field(None, ge=0)
    analysis_version: str = ELF_ANALYSIS_VERSION
    format: Literal["elf"] = "elf"
    file_name: str
    file_size: int = Field(ge=0)
    elf_type: str
    architecture: str
    bitness: Literal[32, 64]
    endianness: Literal["little", "big"]
    build_id: str | None
    debug_file: str | None
    debug_source: SymbolSource
    exact_size: int = Field(ge=0)
    estimated_size: int = Field(ge=0)
    shared_size: int = Field(ge=0)
    unattributed_size: int = Field(ge=0)
    symbol_coverage: float = Field(ge=0, le=1)
    ownership_coverage: float = Field(ge=0, le=1)
    sections: list[ELFSectionResult]
    classes: list[ELFClassResult]
    symbols: list[ELFSymbolResult]
    warnings: list[str]
    treemap: TreemapResults

    def to_dict(self) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        data["generated_at"] = self.generated_at.isoformat()
        return data
