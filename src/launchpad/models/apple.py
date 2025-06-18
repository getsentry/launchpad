"""Apple-specific models for analysis results."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis, DuplicateFilesInsightResult, FileAnalysis
from .range_mapping import RangeMap
from .treemap import TreemapResults


class AppleAnalysisResults(BaseAnalysisResults):
    """Complete Apple analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: AppleAppInfo = Field(..., description="Apple app information")
    file_analysis: FileAnalysis = Field(..., description="File-level analysis results")
    treemap: TreemapResults | None = Field(None, description="Hierarchical size analysis treemap")
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


class MachOBinaryAnalysis(BaseBinaryAnalysis):
    """Mach-O binary analysis results."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    swift_metadata: SwiftMetadata | None = Field(None, description="Swift-specific metadata")
    range_map: RangeMap | None = Field(
        None,
        description="Range mapping for binary content categorization",
        exclude=True,
    )

    @property
    def has_range_mapping(self) -> bool:
        """Check if range mapping is available."""
        return self.range_map is not None

    @property
    def unmapped_size(self) -> int:
        """Get size of unmapped regions, if range mapping is available."""
        if self.range_map is not None:
            return int(self.range_map.unmapped_size)
        return 0

    @property
    def coverage_percentage(self) -> float:
        """Get coverage percentage, if range mapping is available."""
        if self.range_map is not None:
            report = self.range_map.get_coverage_report()
            return float(report.get("coverage_percentage", 0.0))
        return 0.0


class SwiftMetadata(BaseModel):
    """Swift-specific metadata extracted from the binary."""

    model_config = ConfigDict(frozen=True)

    classes: List[str] = Field(default_factory=list, description="Swift class names")
    protocols: List[str] = Field(default_factory=list, description="Swift protocol names")
    extensions: List[str] = Field(default_factory=list, description="Swift extension names")
    total_metadata_size: int = Field(default=0, ge=0, description="Total Swift metadata size")


class AppleInsightResults(BaseModel):
    """Collection of all insight results."""

    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
