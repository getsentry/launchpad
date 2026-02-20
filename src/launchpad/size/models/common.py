"""Common models shared across platforms."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field

from .treemap import TreemapResults, TreemapType

# Only analyses of the same major version can be compared.
# Analyses with different minor versions will skip treemap comparisons
# so we can update treemap logic and not give users confusing diffs.
# Patch versions are ignored.
ANDROID_ANALYSIS_VERSION = "1.0.0"
APPLE_ANALYSIS_VERSION = "1.2.1"


class BaseAppInfo(BaseModel):
    """Base app information that applies across platforms."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="App display name")
    version: str = Field(..., description="App version")
    build: str = Field(..., description="Build number")
    app_id: str = Field(..., description="App ID (bundle id on iOS, package name on Android)")
    cli_version: str | None = Field(None, description="sentry-cli version used for uploading")


class FileAnalysis(BaseModel):
    """Analysis results for files and directories in the app bundle."""

    model_config = ConfigDict(frozen=True)

    items: List[FileInfo] = Field(..., description="List of all files and directories in the bundle")

    @property
    def files(self) -> List[FileInfo]:
        """Files only (excluding directories)."""
        return [item for item in self.items if not item.is_dir]

    @property
    def directories(self) -> List[FileInfo]:
        """Directories only."""
        return [item for item in self.items if item.is_dir]

    @property
    def total_size(self) -> int:
        """Total size in bytes including both files and directory entries."""
        return sum(item.size for item in self.items)


class FileInfo(BaseModel):
    """Information about a file or directory in the app bundle.

    Note: Only path, hash, and children are serialized. Other fields are excluded
    to reduce JSON size - they're only needed for internal processing.
    """

    model_config = ConfigDict(frozen=True)

    #
    # Serialized fields
    #
    path: str = Field(..., description="Relative path in the bundle")
    hash: str = Field(..., description="MD5 hash of file contents or directory identifier")
    # Some files can be further broken down, e.g. asset catalog files. We are NOT storing files themselves
    # in a tree structure, this is only for special cases.
    children: List[FileInfo] = Field(default_factory=list, description="Children of the file")

    #
    # Excluded fields
    #
    full_path: Path | None = Field(..., exclude=True, description="Fully qualified path to the file or directory")
    size: int = Field(
        ...,
        ge=0,
        exclude=True,
        description="Raw file size in bytes with no filesystem block size adjustments (0 for directories)",
    )
    file_type: str = Field(..., exclude=True, description="File type/extension or 'directory'")
    treemap_type: TreemapType = Field(..., exclude=True, description="Type for treemap visualization")
    is_dir: bool = Field(..., exclude=True, description="True if this is a directory, False if it's a file")
    # Asset catalog specific fields
    idiom: str | None = Field(default=None, exclude=True, description="Device idiom for asset catalog images")
    colorspace: str | None = Field(default=None, exclude=True, description="Color space for asset catalog images")
    scale: int | None = Field(default=None, exclude=True, description="Scale factor for asset catalog images")
    # Directory-specific fields
    size_including_children: int | None = Field(
        default=None,
        exclude=True,
        description="Total size including all children (for directories). None for files.",
    )


class ComponentType(IntEnum):
    """Type of modular app component. Compatible with backend MetricsArtifactType.

    NOTE: The backend model must be updated FIRST if this enum is changed, so that it
    doesn't reject the new values.
    """

    MAIN_ARTIFACT = 0
    """The main artifact."""
    WATCH_ARTIFACT = 1
    """An embedded watch artifact."""
    ANDROID_DYNAMIC_FEATURE = 2
    """An embedded Android dynamic feature artifact."""
    APP_CLIP_ARTIFACT = 3
    """An embedded App Clip artifact."""

    @classmethod
    def as_choices(cls) -> tuple[tuple[int, str], ...]:
        """Return choices tuple for compatibility with backend."""
        return (
            (cls.MAIN_ARTIFACT, "main_artifact"),
            (cls.WATCH_ARTIFACT, "watch_artifact"),
            (cls.ANDROID_DYNAMIC_FEATURE, "android_dynamic_feature_artifact"),
            (cls.APP_CLIP_ARTIFACT, "app_clip_artifact"),
        )

    def to_string(self) -> str:
        """Return the string representation for this component type."""
        choices = dict(self.as_choices())
        return choices[self]


class AppComponent(BaseModel):
    """Information about a modular app component (watch app, app extension, dynamic feature, etc.)."""

    model_config = ConfigDict(frozen=True)

    component_type: ComponentType = Field(..., description="Type of component")
    app_id: str = Field(..., description="App ID (bundle id on iOS, package name on Android)")
    name: str = Field(..., description="Component identifier/name")
    path: str = Field(..., description="Relative path in the bundle")
    download_size: int = Field(..., ge=0, description="Estimated download size in bytes")
    install_size: int = Field(..., ge=0, description="Estimated install size in bytes")


class BaseAnalysisResults(BaseModel):
    """Base analysis results structure."""

    model_config = ConfigDict(frozen=True)

    # Analysis metadata
    generated_at: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")
    analysis_duration: float | None = Field(None, ge=0, description="Analysis duration in seconds")
    analysis_version: str = Field(description="Analysis version")

    file_analysis: FileAnalysis = Field(..., description="File-level analysis results")
    treemap: TreemapResults | None = Field(..., description="Hierarchical size analysis treemap")
    use_si_units: bool = Field(default=False, description="Whether to use SI units for size display")
    download_size: int = Field(..., description="Total estimated download size in bytes (main app + all components)")
    install_size: int = Field(..., description="Total estimated install size in bytes (main app + all components)")
    app_components: List[AppComponent] = Field(
        default_factory=list,
        description="Breakdown of modular app components (main app, watch apps, app clips, dynamic features).",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable datetime."""
        data = self.model_dump(exclude_none=True)
        data["generated_at"] = self.generated_at.isoformat()
        return data
