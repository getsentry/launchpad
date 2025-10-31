"""Apple-specific models for analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from launchpad.parsers.apple.dwarf_relocations_parser import DwarfRelocationsData
from launchpad.size.symbols.partitioner import SymbolInfo

from .common import BaseAnalysisResults, BaseAppInfo
from .insights import (
    AudioCompressionInsightResult,
    DuplicateFilesInsightResult,
    HermesDebugInfoInsightResult,
    ImageOptimizationInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
    LocalizedStringCommentsInsightResult,
    LooseImagesInsightResult,
    MainBinaryExportMetadataResult,
    SmallFilesInsightResult,
    StripBinaryInsightResult,
    UnnecessaryFilesInsightResult,
    VideoCompressionInsightResult,
)


class AppleAnalysisResults(BaseAnalysisResults):
    """Apple analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: AppleAppInfo = Field(..., description="Apple app information")
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
    primary_icon_name: str | None = Field(None, description="Primary app icon name from Info.plist")
    alternate_icon_names: List[str] = Field(
        default_factory=list, description="Alternate app icon names from Info.plist"
    )
    missing_dsym_binaries: List[str] = Field(
        default_factory=list, description="List of binary names that don't have corresponding dSYM files"
    )


class AppleInsightResults(BaseModel):
    """Collection of all insight results."""

    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    large_images: LargeImageFileInsightResult | None = Field(None, description="Large image files analysis")
    large_audios: LargeAudioFileInsightResult | None = Field(None, description="Large audio files analysis")
    large_videos: LargeVideoFileInsightResult | None = Field(None, description="Large video files analysis")
    strip_binary: StripBinaryInsightResult | None = Field(None, description="Strip binary analysis")
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
    audio_compression: AudioCompressionInsightResult | None = Field(None, description="Audio compression analysis")
    video_compression: VideoCompressionInsightResult | None = Field(None, description="Video compression analysis")
    alternate_icons_optimization: ImageOptimizationInsightResult | None = Field(
        None, description="Alternate app icons optimization analysis"
    )


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
class LinkEditInfo:
    """Link edit segment components extracted from various load commands in __LINKEDIT.

    Consolidates all __LINKEDIT segment data including symbol tables, DYLD info, and code signature.
    """

    # Segment
    segment_size: int = 0

    # Symbol tables (from LC_SYMTAB)
    symbol_table_size: int = 0
    string_table_size: int = 0

    # Debugging (from LC_FUNCTION_STARTS)
    function_starts_size: int = 0

    # DYLD (from LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE)
    chained_fixups_size: int = 0
    export_trie_size: int = 0

    # Code signing (from LC_CODE_SIGNATURE)
    code_signature_size: int = 0
    code_signature_offset: int = 0


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
    segments: List[SegmentInfo]
    load_commands: List[LoadCommandInfo]
    swift_metadata: SwiftMetadata | None = None
    symbol_info: SymbolInfo | None = None
    header_size: int = 0
    dwarf_relocations: DwarfRelocationsData | None = None
    strippable_symbols_size: int = 0
    linkedit_info: LinkEditInfo | None = None


@dataclass
class SwiftMetadata:
    """Swift-specific metadata extracted from the binary."""

    protocol_conformances: List[str]
