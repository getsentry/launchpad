"""Android manifest models and utilities."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AndroidApplication(BaseModel):
    """Android application information from manifest."""

    model_config = ConfigDict(frozen=True)

    icon_path: Optional[str] = Field(None, description="Path to application icon")
    label: Optional[str] = Field(None, description="Application label")


class AndroidManifest(BaseModel):
    """Android manifest information."""

    model_config = ConfigDict(frozen=True)

    package_name: str = Field(..., description="Android package name")
    version_name: Optional[str] = Field(None, description="App version name")
    version_code: Optional[str] = Field(None, description="App version code")
    min_sdk_version: int = Field(..., description="Minimum SDK version")
    permissions: list[str] = Field(default_factory=list, description="List of app permissions")
    application: AndroidApplication = Field(..., description="Application information")
    is_feature_split: bool = Field(default=False, description="Whether this is a feature split")
