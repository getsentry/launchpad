"""Android manifest models and utilities."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AndroidApplication(BaseModel):
    """Android application information from manifest."""

    model_config = ConfigDict(frozen=True)

    icon_path: str | None = Field(None, description="Path to application icon")
    label: str | None = Field(None, description="Application label")


class AndroidManifest(BaseModel):
    """Android manifest information."""

    model_config = ConfigDict(frozen=True)

    package_name: str = Field(..., description="Android package name")
    version_name: str | None = Field(None, description="App version name")
    version_code: str | None = Field(None, description="App version code")
    min_sdk_version: int = Field(..., description="Minimum SDK version")
    permissions: list[str] = Field(default_factory=list, description="List of app permissions")
    application: AndroidApplication = Field(..., description="Application information")
    is_feature_split: bool = Field(default=False, description="Whether this is a feature split")


class DeliveryType(str, Enum):
    INSTALL_TIME = "install-time"
    ON_DEMAND = "on-demand"
    FAST_FOLLOW = "fast-follow"
