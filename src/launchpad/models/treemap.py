"""Treemap models for hierarchical size analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field


class TreemapType(str, Enum):
    """Types of elements in the treemap for visualization."""

    # Generic file categories (cross-platform)
    FILES = "files"
    EXECUTABLES = "executables"
    RESOURCES = "resources"
    ASSETS = "assets"
    MANIFESTS = "manifests"
    SIGNATURES = "signatures"

    # iOS-specific categories
    FRAMEWORKS = "frameworks"
    PLISTS = "plists"

    # Android-specific categories
    DEX_FILES = "dex_files"
    NATIVE_LIBRARIES = "native_libraries"
    COMPILED_RESOURCES = "compiled_resources"

    # Binary analysis categories (cross-platform)
    MODULES = "modules"
    CLASSES = "classes"
    METHODS = "methods"
    STRINGS = "strings"
    SYMBOLS = "symbols"

    # iOS binary categories
    DYLD = "dyld"
    MACHO = "macho"
    FUNCTION_STARTS = "function_starts"
    CODE_SIGNATURE = "code_signature"
    EXTERNAL_METHODS = "external_methods"

    # Android binary categories
    DEX_CLASSES = "dex_classes"
    DEX_METHODS = "dex_methods"
    NATIVE_CODE = "native_code"

    # Generic categories
    OTHER = "other"
    UNMAPPED = "unmapped"


class TreemapElement(BaseModel):
    """Hierarchical element in the treemap for size visualization."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Display name of the element")
    install_size: int = Field(..., ge=0, description="Install size in bytes")
    download_size: int = Field(..., ge=0, description="Download size in bytes (compressed)")
    element_type: TreemapType | None = Field(None, description="Type of element for visualization")
    path: str | None = Field(None, description="File or directory path")
    is_directory: bool = Field(False, description="Whether this element represents a directory")
    children: List[TreemapElement] = Field(default_factory=list, description="Child elements")
    details: Dict[str, Any] = Field(default_factory=dict, description="Platform and context-specific metadata")

    @property
    def is_leaf(self) -> bool:
        """Check if this is a leaf node (no children)."""
        return len(self.children) == 0

    @property
    def total_install_size(self) -> int:
        """Total install size including all children."""
        return self.install_size + sum(child.total_install_size for child in self.children)

    @property
    def total_download_size(self) -> int:
        """Total download size including all children."""
        return self.download_size + sum(child.total_download_size for child in self.children)

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary for visualization."""
        result: Dict[str, Any] = {
            "name": self.name,
            "value": self.install_size,  # Primary size for visualization
            "downloadSize": self.download_size,
            "installSize": self.install_size,
            "isDirectory": self.is_directory,
        }

        if self.element_type:
            result["type"] = self.element_type.value

        if self.path:
            result["path"] = self.path

        if self.details:
            result["details"] = self.details

        if self.children:
            result["children"] = [child.to_json_dict() for child in self.children]

        return result


class TreemapResults(BaseModel):
    """Complete treemap analysis results."""

    model_config = ConfigDict(frozen=True)

    root: TreemapElement = Field(..., description="Root element of the treemap")
    total_install_size: int = Field(..., ge=0, description="Total install size")
    total_download_size: int = Field(..., ge=0, description="Total download size")
    file_count: int = Field(..., ge=0, description="Total number of files analyzed")
    category_breakdown: Dict[str, Dict[str, int]] = Field(
        default_factory=dict, description="Size breakdown by category"
    )
    platform: str = Field(default="unknown", description="Platform (ios, android, etc.)")

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "app": self.root.to_json_dict(),
            "metadata": {
                "platform": self.platform,
                "totalInstallSize": self.total_install_size,
                "totalDownloadSize": self.total_download_size,
                "fileCount": self.file_count,
                "categoryBreakdown": self.category_breakdown,
            },
        }
