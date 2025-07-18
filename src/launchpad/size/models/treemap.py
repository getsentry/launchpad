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
    FONTS = "fonts"

    # Apple-specific categories
    FRAMEWORKS = "frameworks"
    PLISTS = "plists"
    EXTENSIONS = "extensions"  # App extensions and plugins

    # Android-specific categories
    DEX = "dex"
    NATIVE_LIBRARIES = "native_libraries"
    COMPILED_RESOURCES = "compiled_resources"

    # Binary analysis categories (cross-platform)
    MODULES = "modules"
    CLASSES = "classes"
    METHODS = "methods"
    STRINGS = "strings"
    SYMBOLS = "symbols"

    # Apple binary categories
    DYLD = "dyld"
    MACHO = "macho"
    FUNCTION_STARTS = "function_starts"
    CODE_SIGNATURE = "code_signature"
    EXTERNAL_METHODS = "external_methods"

    # Binary section categories
    BINARY = "binary"

    # Generic categories
    OTHER = "other"
    UNMAPPED = "unmapped"


# Mapping from file types to TreemapType
FILE_TYPE_TO_TREEMAP_TYPE: dict[str, TreemapType] = {
    # Binary types
    "macho": TreemapType.EXECUTABLES,
    "executable": TreemapType.EXECUTABLES,
    "dex": TreemapType.DEX,
    # Asset types
    "png": TreemapType.ASSETS,
    "jpg": TreemapType.ASSETS,
    "jpeg": TreemapType.ASSETS,
    "gif": TreemapType.ASSETS,
    "pdf": TreemapType.ASSETS,
    "car": TreemapType.ASSETS,
    # Resource types
    "nib": TreemapType.RESOURCES,
    "storyboard": TreemapType.RESOURCES,
    "strings": TreemapType.RESOURCES,
    "lproj": TreemapType.RESOURCES,
    "arsc": TreemapType.RESOURCES,
    "xml": TreemapType.RESOURCES,
    # Font types
    "ttf": TreemapType.FONTS,
    "otf": TreemapType.FONTS,
    # Other types
    "plist": TreemapType.PLISTS,
    "framework": TreemapType.FRAMEWORKS,
    "appex": TreemapType.EXTENSIONS,
}


class TreemapElement(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Display name of the element")
    install_size: int = Field(..., ge=0, description="Install size in bytes")
    download_size: int = Field(..., ge=0, description="Download size in bytes (compressed)")
    element_type: TreemapType | None = Field(None, description="Type of element for visualization")
    path: str | None = Field(None, description="Relative file or directory path")
    is_directory: bool = Field(False, description="Whether this element represents a directory")
    children: List[TreemapElement] = Field(default_factory=list, description="Child elements")
    details: Dict[str, Any] = Field(default_factory=dict, description="Platform and context-specific metadata")

    @property
    def is_leaf(self) -> bool:
        """Check if this is a leaf node (no children)."""
        return len(self.children) == 0


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
