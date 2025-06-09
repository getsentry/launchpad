"""iOS-specific models for analysis results."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis


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

    bundle_id: str = Field(..., description="Bundle identifier")
    minimum_os_version: str = Field(..., description="Minimum iOS version")
    supported_platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    sdk_version: Optional[str] = Field(None, description="iOS SDK version used for build")


class IOSBinaryAnalysis(BaseBinaryAnalysis):
    """iOS-specific binary analysis results."""

    model_config = ConfigDict(frozen=True)

    swift_metadata: Optional[SwiftMetadata] = Field(None, description="Swift-specific metadata")


class IOSAnalysisResults(BaseAnalysisResults):
    """Complete iOS analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: IOSAppInfo = Field(..., description="iOS app information")
    binary_analysis: IOSBinaryAnalysis = Field(..., description="iOS binary analysis results")


# Backwards compatibility aliases - can be removed once all references are updated
AppInfo = IOSAppInfo
BinaryAnalysis = IOSBinaryAnalysis
AnalysisResults = IOSAnalysisResults
