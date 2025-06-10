"""Treemap models for hierarchical size analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TreemapType(str, Enum):
    """Types of elements in the treemap for visualization."""

    # File-based categories
    FILES = "files"
    EXECUTABLES = "executables"
    FRAMEWORKS = "frameworks"
    RESOURCES = "resources"
    ASSETS = "assets"
    PLISTS = "plists"

    # Binary analysis categories (for future use)
    MODULES = "modules"
    STRINGS = "strings"
    DYLD = "dyld"
    MACHO = "macho"
    FUNCTION_STARTS = "function_starts"
    CODE_SIGNATURE = "code_signature"
    EXTERNAL_METHODS = "external_methods"

    # Generic categories
    OTHER = "other"
    UNMAPPED = "unmapped"


class TreemapElement(BaseModel):
    """Hierarchical element in the treemap for size visualization."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Display name of the element")
    install_size: int = Field(..., ge=0, description="Install size in bytes")
    download_size: int = Field(..., ge=0, description="Download size in bytes (compressed)")
    element_type: Optional[TreemapType] = Field(
        None, description="Type of element for visualization"
    )
    path: Optional[str] = Field(None, description="File path (for leaf nodes)")
    children: List[TreemapElement] = Field(default_factory=list, description="Child elements")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

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

    def add_child(self, child: TreemapElement) -> None:
        """Add a child element (creates a new TreemapElement since model is frozen)."""
        # Since the model is frozen, we need to work around this differently
        # This method is for convenience but won't actually modify the frozen model
        raise NotImplementedError("Cannot modify frozen model. Use TreemapBuilder instead.")

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary for visualization."""
        result: Dict[str, Any] = {
            "name": self.name,
            "value": self.install_size,  # Primary size for visualization
            "downloadSize": self.download_size,
            "installSize": self.install_size,
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

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "app": self.root.to_json_dict(),
            "metadata": {
                "totalInstallSize": self.total_install_size,
                "totalDownloadSize": self.total_download_size,
                "fileCount": self.file_count,
                "categoryBreakdown": self.category_breakdown,
            },
        }
