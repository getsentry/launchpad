"""Simple data model for binary components used in size analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, Field


class BinaryTag(Enum):
    """Enum for categorizing binary content types."""

    # String categories
    CFSTRINGS = "cfstrings"
    SWIFT_FILE_PATHS = "swift_file_paths"
    METHOD_SIGNATURES = "method_signatures"
    OBJC_TYPE_STRINGS = "objc_type_strings"
    C_STRINGS = "c_strings"

    # Header and metadata
    HEADERS = "headers"
    LOAD_COMMANDS = "load_commands"

    # Executable code
    TEXT_SEGMENT = "text_segment"
    FUNCTION_STARTS = "function_starts"
    EXTERNAL_METHODS = "external_methods"

    # Code signature
    CODE_SIGNATURE = "code_signature"

    # DYLD info categories
    DYLD = "dyld"  # Parent category for all DYLD-related ranges
    DYLD_REBASE = "dyld_rebase"
    DYLD_BIND = "dyld_bind"
    DYLD_LAZY_BIND = "dyld_lazy_bind"
    DYLD_EXPORTS = "dyld_exports"
    DYLD_FIXUPS = "dyld_fixups"
    DYLD_STRING_TABLE = "dyld_string_table"

    # Binary modules/classes
    OBJC_CLASSES = "objc_classes"
    SWIFT_METADATA = "swift_metadata"
    BINARY_MODULES = "binary_modules"

    # Data sections
    DATA_SEGMENT = "data_segment"
    CONST_DATA = "const_data"

    # Unwind and debug info
    UNWIND_INFO = "unwind_info"
    DEBUG_INFO = "debug_info"

    # Unmapped regions
    UNMAPPED = "unmapped"


class BinaryComponent(BaseModel):
    """Represents a component of a binary with its size and categorization."""

    name: str = Field(..., description="Name of the component (e.g., section name, command name)")
    size: int = Field(..., ge=0, description="Size of the component in bytes")
    tag: BinaryTag = Field(..., description="Category tag for the component")
    description: str | None = Field(None, description="Optional description of the component")

    def __str__(self) -> str:
        """String representation of the component."""
        return f"{self.name} ({self.tag.value}): {self.size} bytes"


class BinaryAnalysis(BaseModel):
    """Complete analysis of a binary with all its components."""

    file_path: str = Field(..., description="Path to the analyzed binary file")
    total_size: int = Field(..., ge=0, description="Total size of the binary file")
    components: List[BinaryComponent] = Field(default_factory=list, description="List of binary components")

    @property
    def analyzed_size(self) -> int:
        """Total size of all analyzed components."""
        return sum(component.size for component in self.components)

    @property
    def unanalyzed_size(self) -> int:
        """Size not covered by component analysis."""
        return max(0, self.total_size - self.analyzed_size)

    @property
    def coverage_percentage(self) -> float:
        """Percentage of file covered by analysis."""
        if self.total_size == 0:
            return 100.0
        return (self.analyzed_size / self.total_size) * 100.0

    def size_by_tag(self) -> Dict[BinaryTag, int]:
        """Get total size for each binary tag."""
        sizes: Dict[BinaryTag, int] = {}
        for component in self.components:
            sizes[component.tag] = sizes.get(component.tag, 0) + component.size
        return sizes

    def get_components_by_tag(self, tag: BinaryTag) -> List[BinaryComponent]:
        """Get all components with a specific tag."""
        return [component for component in self.components if component.tag == tag]

    def add_component(self, name: str, size: int, tag: BinaryTag, description: str | None = None) -> None:
        """Add a component to the analysis."""
        if size > 0:  # Only add components with positive size
            component = BinaryComponent(name=name, size=size, tag=tag, description=description)
            self.components.append(component)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the binary analysis."""
        return {
            "file_path": self.file_path,
            "total_size": self.total_size,
            "analyzed_size": self.analyzed_size,
            "unanalyzed_size": self.unanalyzed_size,
            "coverage_percentage": round(self.coverage_percentage, 2),
            "component_count": len(self.components),
            "size_by_tag": {tag.value: size for tag, size in self.size_by_tag().items()},
        }
