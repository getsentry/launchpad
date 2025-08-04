"""Apple-specific models for analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import lief

from pydantic import BaseModel, ConfigDict, Field

from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.parsers.apple.objc_symbol_type_aggregator import ObjCSymbolTypeGroup
from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeGroup

from .common import BaseAnalysisResults, BaseAppInfo
from .insights import (
    DuplicateFilesInsightResult,
    HermesDebugInfoInsightResult,
    ImageOptimizationInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
    LocalizedStringCommentsInsightResult,
    LocalizedStringInsightResult,
    LooseImagesInsightResult,
    MainBinaryExportMetadataResult,
    SmallFilesInsightResult,
    StripBinaryInsightResult,
    UnnecessaryFilesInsightResult,
)


class AppleAnalysisResults(BaseAnalysisResults):
    """Complete Apple analysis results."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    app_info: AppleAppInfo = Field(..., description="Apple app information")
    binary_analysis: List[MachOBinaryAnalysis] = Field(
        default_factory=list,
        description="Apple binary analysis results",
        exclude=True,
    )
    insights: AppleInsightResults | None = Field(
        description="Generated insights from the analysis",
    )


class AppleAppInfo(BaseAppInfo):
    """Apple-specific app information."""

    model_config = ConfigDict(frozen=True)

    executable: str = Field(..., description="Main executable name")
    minimum_os_version: str = Field(..., description="Minimum app version")
    supported_platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    sdk_version: str | None = Field(None, description="App SDK version used for build")
    is_simulator: bool = Field(False, description="If the app is a simulator build")
    codesigning_type: str | None = Field(
        None, description="Type of codesigning used (development, adhoc, appstore, enterprise)"
    )
    profile_name: str | None = Field(None, description="Name of the provisioning profile used")
    profile_expiration_date: str | None = Field(None, description="Expiration date of the provisioning profile")
    certificate_expiration_date: str | None = Field(None, description="Expiration date of the developer certificate")
    is_code_signature_valid: bool = Field(True, description="Whether the app's code signature is valid")
    code_signature_errors: List[str] = Field(
        default_factory=list, description="List of code signature validation errors"
    )
    main_binary_uuid: str | None = Field(None, description="UUID of the main binary")


@dataclass
class SegmentInfo:
    """Extracted segment information from LIEF data."""

    name: str
    sections: List[SectionInfo]
    size: int


@dataclass
class SectionInfo:
    """Extracted section information from LIEF data."""

    name: str
    size: int


@dataclass
class LoadCommandInfo:
    """Extracted load command information from LIEF data."""

    name: str
    size: int


@dataclass
class DyldInfo:
    """DYLD-specific information extracted from related DYLD load commands."""

    chained_fixups_size: int = 0
    export_trie_size: int = 0


@dataclass
class MachOBinaryAnalysis:
    """Mach-O binary analysis results."""

    binary_absolute_path: Path
    binary_relative_path: Path
    executable_size: int
    is_main_binary: bool
    architectures: List[str]
    linked_libraries: List[str]
    objc_method_names: List[str]
    # Lief types cannot be used after the binary is closed
    # so we need to extract the segment/section data into dataclasses
    segments: List[SegmentInfo]
    load_commands: List[LoadCommandInfo]
    swift_metadata: SwiftMetadata | None = None
    # TODO(telkins): try to remove the lief types from this model
    # it's only working by coincidence right now
    symbol_info: SymbolInfo | None = None
    header_size: int = 0
    dyld_info: DyldInfo | None = None


@dataclass
class SwiftMetadata:
    """Swift-specific metadata extracted from the binary."""

    protocol_conformances: List[str]


class AppleInsightResults(BaseModel):
    """Collection of all insight results."""

    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    large_images: LargeImageFileInsightResult | None = Field(None, description="Large image files analysis")
    large_videos: LargeVideoFileInsightResult | None = Field(None, description="Large video files analysis")
    large_audio: LargeAudioFileInsightResult | None = Field(None, description="Large audio files analysis")
    strip_binary: StripBinaryInsightResult | None = Field(None, description="Strip binary analysis")
    localized_strings: LocalizedStringInsightResult | None = Field(None, description="Localized strings analysis")
    localized_strings_minify: LocalizedStringCommentsInsightResult | None = Field(
        None, description="Localized strings comments analysis"
    )
    small_files: SmallFilesInsightResult | None = Field(None, description="Small files analysis")
    loose_images: LooseImagesInsightResult | None = Field(
        None, description="Loose images not in asset catalogs analysis"
    )
    hermes_debug_info: HermesDebugInfoInsightResult | None = Field(None, description="Hermes debug info analysis")
    image_optimization: ImageOptimizationInsightResult | None = Field(None, description="Image optimization analysis")
    main_binary_exported_symbols: MainBinaryExportMetadataResult | None = Field(
        None, description="Main binary exported symbols analysis"
    )
    unnecessary_files: UnnecessaryFilesInsightResult | None = Field(None, description="Unnecessary files analysis")


@dataclass
class SymbolInfo:
    symbol_sizes: List[SymbolSize]
    swift_type_groups: List[SwiftSymbolTypeGroup]
    objc_type_groups: List[ObjCSymbolTypeGroup]
    static_inits: List[lief.Symbol | str]
    strippable_symbols_size: int = 0

    def get_symbols_by_section(self) -> dict[str, list[tuple[str, str, int, int]]]:
        """Group symbols by their section name.

        Returns:
            Dictionary mapping section names to lists of (module, name, address, size) tuples
        """
        symbols_by_section: dict[str, list[tuple[str, str, int, int]]] = {}

        for group in self.swift_type_groups:
            for symbol in group.symbols:
                section_name = str(symbol.section.name) if symbol.section else "unknown"
                if section_name not in symbols_by_section:
                    symbols_by_section[section_name] = []

                symbols_by_section[section_name].append((group.module, group.type_name, symbol.address, symbol.size))

        for group in self.objc_type_groups:
            for symbol in group.symbols:
                section_name = str(symbol.section.name) if symbol.section else "unknown"
                if section_name not in symbols_by_section:
                    symbols_by_section[section_name] = []

                method_name = group.method_name or "class"
                symbols_by_section[section_name].append((group.class_name, method_name, symbol.address, symbol.size))

        return symbols_by_section
