"""iOS-specific models for analysis results."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis, FileAnalysis
from .range_mapping import RangeMap
from .treemap import TreemapResults


class SwiftMetadata(BaseModel):
    """Swift-specific metadata extracted from the binary."""

    model_config = ConfigDict(frozen=True)

    classes: List[str] = Field(default_factory=list, description="Swift class names")
    protocols: List[str] = Field(default_factory=list, description="Swift protocol names")
    extensions: List[str] = Field(default_factory=list, description="Swift extension names")
    total_metadata_size: int = Field(default=0, ge=0, description="Total Swift metadata size")


class IOSAppInfo(BaseAppInfo):
    """iOS-specific app information."""

    model_config = ConfigDict(frozen=True)

    executable: str = Field(..., description="Main executable name")
    bundle_id: str = Field(..., description="Bundle identifier")
    minimum_os_version: str = Field(..., description="Minimum iOS version")
    supported_platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    sdk_version: str | None = Field(None, description="iOS SDK version used for build")


class IOSBinaryAnalysis(BaseBinaryAnalysis):
    """iOS-specific binary analysis results."""

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


class IOSAnalysisResults(BaseAnalysisResults):
    """Complete iOS analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: IOSAppInfo = Field(..., description="iOS app information")
    file_analysis: FileAnalysis = Field(..., description="File-level analysis results")
    binary_analysis: IOSBinaryAnalysis = Field(..., description="iOS binary analysis results")
    treemap: TreemapResults | None = Field(None, description="Hierarchical size analysis treemap")

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
