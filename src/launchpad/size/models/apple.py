"""Apple-specific models for analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from launchpad.parsers.apple.objc_symbol_type_aggregator import ObjCSymbolTypeGroup
from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeGroup
from launchpad.size.models.binary_component import BinaryAnalysis

from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis, FileInfo
from .insights import (
    BaseInsightResult,
    DuplicateFilesInsightResult,
    HermesDebugInfoInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
)


@dataclass
class LooseImageGroup:
    """Group of loose image files with the same canonical name."""

    canonical_name: str
    images: List[FileInfo]

    @property
    def total_size(self) -> int:
        """Total size of all images in this group."""
        return sum(img.size for img in self.images)


class AppleAnalysisResults(BaseAnalysisResults):
    """Complete Apple analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: AppleAppInfo = Field(..., description="Apple app information")
    binary_analysis: List[MachOBinaryAnalysis] = Field(
        default_factory=list,
        description="Apple binary analysis results",
        exclude=True,
    )
    insights: AppleInsightResults | None = Field(
        description="Generated insights from the analysis",
    )
    download_size: int = Field(..., description="Estimated download size in bytes")
    install_size: int = Field(..., description="Estimated install size in bytes")


class LocalizedStringInsightResult(BaseInsightResult):
    """Results from localized string analysis."""

    files: List[FileInfo] = Field(..., description="Localized strings files exceeding 100KB threshold")


class SmallFilesInsightResult(BaseInsightResult):
    """Results from small files analysis."""

    files: List[FileInfo] = Field(..., description="Files smaller than filesystem block size")
    file_count: int = Field(..., description="Number of small files found")


class LooseImagesInsightResult(BaseInsightResult):
    """Results from loose images analysis."""

    image_groups: List[LooseImageGroup] = Field(
        ..., description="Groups of loose images that could be moved to asset catalogs"
    )
    total_file_count: int = Field(..., description="Total number of loose image files found")


@dataclass
class OptimizableImageFile:
    """Information about an image file that can be optimized."""

    file_info: FileInfo

    current_size: int

    # Minification savings (optimizing current format)
    minify_savings: int = 0
    minified_size: int | None = None

    # HEIC conversion savings (converting to HEIC format)
    conversion_savings: int = 0
    heic_size: int | None = None

    @property
    def potential_savings(self) -> int:
        """Calculate total potential savings from the best optimization."""
        return max(self.minify_savings, self.conversion_savings)

    @property
    def best_optimization_type(self) -> str:
        """Return the optimization type that provides the most savings."""
        if self.conversion_savings > self.minify_savings:
            return "convert_to_heic"
        elif self.minify_savings > 0:
            return "minify"
        else:
            return "none"


class ImageOptimizationInsightResult(BaseInsightResult):
    """Results from image optimization analysis."""

    optimizable_files: List[OptimizableImageFile] = Field(
        ..., description="Files that can be optimized with potential savings"
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
    is_code_signature_valid: bool = Field(True, description="Whether the app's code signature is valid")
    code_signature_errors: List[str] = Field(
        default_factory=list, description="List of code signature validation errors"
    )


class MachOBinaryAnalysis(BaseBinaryAnalysis):
    """Mach-O binary analysis results."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    binary_path: Path = Field(..., description="Fully qualified path to the binary within the app bundle")
    swift_metadata: SwiftMetadata | None = Field(None, description="Swift-specific metadata")
    binary_analysis: BinaryAnalysis | None = Field(
        None,
        description="Binary component analysis for size categorization",
        exclude=True,
    )
    symbol_info: SymbolInfo | None = Field(None, description="Symbol information", exclude=True)
    objc_method_names: List[str] = Field(default_factory=list, description="Objective-C method names", exclude=True)


class StripBinaryFileInfo(BaseModel):
    """Savings information from stripping a Mach-O binary."""

    file_path: str = Field(..., description="Path to the binary file within the app bundle")
    debug_sections_savings: int = Field(..., ge=0, description="Savings from removing debug sections")
    symbol_table_savings: int = Field(..., ge=0, description="Savings from removing symbol table")
    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes from stripping debug content")


class StripBinaryInsightResult(BaseInsightResult):
    """Results from strip binary analysis."""

    files: List[StripBinaryFileInfo] = Field(..., description="Files that could save size by stripping the binary")
    total_debug_sections_savings: int = Field(..., ge=0, description="Total potential savings from debug sections")
    total_symbol_table_savings: int = Field(..., ge=0, description="Total potential savings from symbol tables")


class SwiftMetadata(BaseModel):
    """Swift-specific metadata extracted from the binary."""

    model_config = ConfigDict(frozen=True)

    protocol_conformances: List[str] = Field(default_factory=list, description="Swift protocol conformance names")


class AppleInsightResults(BaseModel):
    """Collection of all insight results."""

    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    large_images: LargeImageFileInsightResult | None = Field(None, description="Large image files analysis")
    large_videos: LargeVideoFileInsightResult | None = Field(None, description="Large video files analysis")
    large_audio: LargeAudioFileInsightResult | None = Field(None, description="Large audio files analysis")
    strip_binary: StripBinaryInsightResult | None = Field(None, description="Strip binary analysis")
    localized_strings: LocalizedStringInsightResult | None = Field(None, description="Localized strings analysis")
    small_files: SmallFilesInsightResult | None = Field(None, description="Small files analysis")
    loose_images: LooseImagesInsightResult | None = Field(
        None, description="Loose images not in asset catalogs analysis"
    )
    hermes_debug_info: HermesDebugInfoInsightResult | None = Field(None, description="Hermes debug info analysis")
    image_optimization: ImageOptimizationInsightResult | None = Field(None, description="Image optimization analysis")


@dataclass
class SymbolInfo:
    swift_type_groups: List[SwiftSymbolTypeGroup]
    objc_type_groups: List[ObjCSymbolTypeGroup]
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
