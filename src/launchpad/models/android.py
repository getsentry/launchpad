"""Android-specific models for analysis results (placeholder for future implementation)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo


class AndroidMetadata(BaseModel):
    """Android-specific metadata extracted from the APK/AAB."""

    model_config = ConfigDict(frozen=True)

    # Placeholder fields - to be implemented based on Android analysis needs
    # permissions: List[str] = Field(default_factory=list, description="App permissions")
    # activities: List[str] = Field(default_factory=list, description="Android activities")
    # services: List[str] = Field(default_factory=list, description="Android services")


class AndroidAppInfo(BaseAppInfo):
    """Android-specific app information."""

    model_config = ConfigDict(frozen=True)

    # Android-specific fields to be added:
    package_name: str = Field(..., description="Android package name")


class AndroidAnalysisResults(BaseAnalysisResults):
    """Complete Android analysis results."""

    model_config = ConfigDict(frozen=True)

    app_info: AndroidAppInfo = Field(..., description="Android app information")
