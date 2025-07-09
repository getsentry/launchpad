"""Apple-specific models for analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from launchpad.parsers.apple.objc_symbol_type_aggregator import ObjCSymbolTypeGroup
from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeGroup

from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis
from .insights import (
    BaseInsightResult,
    DuplicateFilesInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
)
from .range_mapping import RangeMap


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

    @property
    def download_size(self) -> int:
        """Estimated download size"""
        if self.treemap:
            return self.treemap.total_download_size
        return self.file_analysis.total_size  # TODO: Implement download size calculation

    @property
    def install_size(self) -> int:
        """Estimated install size"""
        if self.treemap:
            return self.treemap.total_install_size
        return self.file_analysis.total_size  # TODO: Implement install size calculation


class AppleAppInfo(BaseAppInfo):
    """Apple-specific app information."""

    model_config = ConfigDict(frozen=True)

    executable: str = Field(..., description="Main executable name")
    bundle_id: str = Field(..., description="Bundle identifier")
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
    range_map: RangeMap | None = Field(
        None,
        description="Range mapping for binary content categorization",
        exclude=True,
    )
    symbol_info: SymbolInfo | None = Field(None, description="Symbol information", exclude=True)
    objc_method_names: List[str] = Field(default_factory=list, description="Objective-C method names", exclude=True)


class StripBinaryFileInfo(BaseModel):
    """Savings information from stripping a Mach-O binary."""

    macho_binary: MachOBinaryAnalysis = Field(..., description="Mach-O binary analysis")
    install_size_saved: int = Field(..., description="Install size saved by stripping the binary")
    download_size_saved: int = Field(..., description="Download size saved by stripping the binary")


class StripBinaryInsightResult(BaseInsightResult):
    """Results from strip binary analysis."""

    files: List[StripBinaryFileInfo] = Field(..., description="Files that could save size by stripping the binary")


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


@dataclass
class SymbolInfo:
    swift_type_groups: List[SwiftSymbolTypeGroup]
    objc_type_groups: List[ObjCSymbolTypeGroup]

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
