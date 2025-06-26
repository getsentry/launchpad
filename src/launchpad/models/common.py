"""Common models shared across platforms."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field

from .treemap import TreemapResults, TreemapType


class BaseAppInfo(BaseModel):
    """Base app information that applies across platforms."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="App display name")
    version: str = Field(..., description="App version")
    build: str = Field(..., description="Build number")


class BaseBinaryAnalysis(BaseModel):
    """Base binary analysis that applies across platforms."""

    model_config = ConfigDict(frozen=True)

    executable_size: int = Field(..., ge=0, description="Main executable size in bytes")
    architectures: List[str] = Field(..., description="CPU architectures")
    linked_libraries: List[str] = Field(default_factory=list, description="Linked dynamic libraries")
    sections: Dict[str, int] = Field(default_factory=dict, description="Binary sections and their sizes")


class SymbolInfo(BaseModel):
    """Information about a binary symbol."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Symbol name")
    mangled_name: str | None = Field(None, description="Mangled symbol name")
    size: int = Field(..., ge=0, description="Symbol size in bytes")
    type: str = Field(..., description="Symbol type")


class FileAnalysis(BaseModel):
    """Analysis results for files in the app bundle."""

    model_config = ConfigDict(frozen=True)

    files: List[FileInfo] = Field(..., description="List of all files in the bundle")

    @property
    def total_size(self) -> int:
        """Total bundle size in bytes."""
        return sum(f.size for f in self.files)

    @property
    def file_count(self) -> int:
        """Total number of files."""
        return len(self.files)

    @property
    def file_type_sizes(self) -> Dict[str, int]:
        """Total size by file type."""
        return {file.file_type: file.size for file in self.files}


class FileInfo(BaseModel):
    """Information about a file in the app bundle."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Relative path in the bundle")
    size: int = Field(..., ge=0, description="File size in bytes")
    file_type: str = Field(..., description="File type/extension")
    hash_md5: str = Field(..., description="MD5 hash of file contents")
    treemap_type: TreemapType = Field(..., description="Type for treemap visualization")


class BaseAnalysisResults(BaseModel):
    """Base analysis results structure."""

    model_config = ConfigDict(frozen=True)
    generated_at: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")
    analysis_duration: float | None = Field(None, ge=0, description="Analysis duration in seconds")
    file_analysis: FileAnalysis = Field(..., description="File-level analysis results")
    treemap: TreemapResults | None = Field(..., description="Hierarchical size analysis treemap")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable datetime."""
        data = self.model_dump()
        data["generated_at"] = self.generated_at.isoformat()
        return data


class ImageInsight(BaseModel):
    """Image optimization potential insight."""

    model_config = ConfigDict(frozen=True)

    image_path: str = Field(..., description="Relative path in the artifact")
    insight: str = Field(..., description="Insight about the image")
