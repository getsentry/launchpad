"""Pydantic models for analysis results."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class FileInfo(BaseModel):
    """Information about a single file in the app bundle."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Relative path within the bundle")
    size: int = Field(..., ge=0, description="File size in bytes")
    file_type: str = Field(..., description="File extension/type")
    hash_md5: Optional[str] = Field(None, description="MD5 hash of file contents")


class DuplicateFileGroup(BaseModel):
    """Group of duplicate files found in the bundle."""

    model_config = ConfigDict(frozen=True)

    files: List[FileInfo] = Field(..., min_length=2, description="List of duplicate files")
    potential_savings: int = Field(..., ge=0, description="Potential size savings in bytes")

    @property
    def duplicate_count(self) -> int:
        """Number of duplicate files (excluding the original)."""
        return len(self.files) - 1


class SymbolInfo(BaseModel):
    """Information about a binary symbol."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Symbol name")
    mangled_name: Optional[str] = Field(None, description="Mangled symbol name")
    size: int = Field(..., ge=0, description="Symbol size in bytes")
    section: str = Field(..., description="Binary section containing the symbol")
    symbol_type: str = Field(..., description="Type of symbol (function, data, etc.)")


class SwiftMetadata(BaseModel):
    """Swift-specific metadata extracted from the binary."""

    model_config = ConfigDict(frozen=True)

    classes: List[str] = Field(default_factory=list, description="Swift class names")
    protocols: List[str] = Field(default_factory=list, description="Swift protocol names")
    extensions: List[str] = Field(default_factory=list, description="Swift extension names")
    total_metadata_size: int = Field(default=0, ge=0, description="Total Swift metadata size")


class AppInfo(BaseModel):
    """Basic information about the analyzed app."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="App display name")
    bundle_id: str = Field(..., description="Bundle identifier")
    version: str = Field(..., description="App version")
    build: str = Field(..., description="Build number")
    executable: str = Field(..., description="Main executable name")
    minimum_os_version: str = Field(..., description="Minimum OS version")
    supported_platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    sdk_version: Optional[str] = Field(None, description="SDK version used for build")


class BinaryAnalysis(BaseModel):
    """Analysis results for binary/executable files."""

    model_config = ConfigDict(frozen=True)

    executable_size: int = Field(..., ge=0, description="Main executable size in bytes")
    architectures: List[str] = Field(..., description="CPU architectures")
    linked_libraries: List[str] = Field(
        default_factory=list, description="Linked dynamic libraries"
    )
    symbols: List[SymbolInfo] = Field(default_factory=list, description="Symbol information")
    swift_metadata: Optional[SwiftMetadata] = Field(None, description="Swift-specific metadata")
    sections: Dict[str, int] = Field(
        default_factory=dict, description="Binary sections and their sizes"
    )

    @property
    def total_symbols_size(self) -> int:
        """Total size of all symbols."""
        return sum(symbol.size for symbol in self.symbols)


class FileAnalysis(BaseModel):
    """Analysis results for files in the app bundle."""

    model_config = ConfigDict(frozen=True)

    total_size: int = Field(..., ge=0, description="Total bundle size in bytes")
    file_count: int = Field(..., ge=0, description="Total number of files")
    files_by_type: Dict[str, List[FileInfo]] = Field(
        default_factory=dict, description="Files grouped by type/extension"
    )
    duplicate_files: List[DuplicateFileGroup] = Field(
        default_factory=list, description="Groups of duplicate files"
    )
    largest_files: List[FileInfo] = Field(
        default_factory=list, description="Largest files in the bundle"
    )

    @property
    def total_duplicate_savings(self) -> int:
        """Total potential savings from removing duplicates."""
        return sum(group.potential_savings for group in self.duplicate_files)

    @property
    def file_type_sizes(self) -> Dict[str, int]:
        """Total size by file type."""
        return {
            file_type: sum(file.size for file in files)
            for file_type, files in self.files_by_type.items()
        }


class AnalysisResults(BaseModel):
    """Complete analysis results for an app bundle."""

    model_config = ConfigDict(frozen=True)

    app_info: AppInfo = Field(..., description="Basic app information")
    file_analysis: FileAnalysis = Field(..., description="File-level analysis results")
    binary_analysis: BinaryAnalysis = Field(..., description="Binary-level analysis results")
    generated_at: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")
    analysis_duration: Optional[float] = Field(
        None, ge=0, description="Analysis duration in seconds"
    )

    @property
    def total_size(self) -> int:
        """Total app bundle size."""
        return self.file_analysis.total_size

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable datetime."""
        data = self.model_dump()
        data["generated_at"] = self.generated_at.isoformat()
        return data
