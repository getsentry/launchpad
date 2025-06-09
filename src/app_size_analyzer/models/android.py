"""Android-specific models for analysis results (placeholder for future implementation)."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict

from .common import BaseAppInfo, BaseBinaryAnalysis, BaseAnalysisResults


# TODO: Implement Android-specific models when Android support is added


class AndroidMetadata(BaseModel):
    """Android-specific metadata extracted from the APK/AAB."""

    model_config = ConfigDict(frozen=True)

    # Placeholder fields - to be implemented based on Android analysis needs
    # permissions: List[str] = Field(default_factory=list, description="App permissions")
    # activities: List[str] = Field(default_factory=list, description="Android activities")
    # services: List[str] = Field(default_factory=list, description="Android services")
    pass


class AndroidAppInfo(BaseAppInfo):
    """Android-specific app information."""

    model_config = ConfigDict(frozen=True)

    # Android-specific fields to be added:
    # package_name: str = Field(..., description="Android package name")
    # min_sdk_version: int = Field(..., description="Minimum SDK version")
    # target_sdk_version: int = Field(..., description="Target SDK version")
    pass


class AndroidBinaryAnalysis(BaseBinaryAnalysis):
    """Android-specific binary analysis results."""

    model_config = ConfigDict(frozen=True)

    # Android-specific fields to be added:
    # dex_analysis: Optional[DexAnalysis] = Field(None, description="DEX file analysis")
    # native_libraries: List[str] = Field(default_factory=list, description="Native .so libraries")
    pass


class AndroidAnalysisResults(BaseAnalysisResults):
    """Complete Android analysis results."""

    model_config = ConfigDict(frozen=True)

    # To be uncommented when Android models are implemented:
    # app_info: AndroidAppInfo = Field(..., description="Android app information")
    # binary_analysis: AndroidBinaryAnalysis = Field(..., description="Android binary analysis results")
    pass
