"""Models for size comparisons between two analyses."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field


class ChangeKind(str, Enum):
    """How a file changed between two analyses."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class FileChange(BaseModel):
    """A single file that was added, removed, or modified between two builds."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Relative path in the bundle")
    kind: ChangeKind = Field(..., description="Whether the file was added, removed, or modified")
    head_size: int = Field(..., ge=0, description="Size in the new (head) build, 0 if removed")
    base_size: int = Field(..., ge=0, description="Size in the old (base) build, 0 if added")

    @property
    def size_diff(self) -> int:
        """Signed size delta (head - base) in bytes."""
        return self.head_size - self.base_size


class CategoryDiff(BaseModel):
    """Size delta for a single treemap category."""

    model_config = ConfigDict(frozen=True)

    category: str = Field(..., description="Treemap category name")
    head_size: int = Field(..., ge=0, description="Category size in the new (head) build")
    base_size: int = Field(..., ge=0, description="Category size in the old (base) build")

    @property
    def size_diff(self) -> int:
        """Signed size delta (head - base) in bytes."""
        return self.head_size - self.base_size


class SizeDiffResults(BaseModel):
    """Result of comparing two size analyses (base -> head)."""

    model_config = ConfigDict(frozen=True)

    app_name: str = Field(..., description="App display name (from the head build)")
    base_label: str = Field(..., description="Human-readable label for the base build, e.g. version (build)")
    head_label: str = Field(..., description="Human-readable label for the head build, e.g. version (build)")

    base_install_size: int = Field(..., ge=0, description="Install size of the base build in bytes")
    head_install_size: int = Field(..., ge=0, description="Install size of the head build in bytes")
    base_download_size: int = Field(..., ge=0, description="Download size of the base build in bytes")
    head_download_size: int = Field(..., ge=0, description="Download size of the head build in bytes")

    category_diffs: List[CategoryDiff] = Field(
        default_factory=list, description="Per-category size deltas, largest absolute change first"
    )
    file_changes: List[FileChange] = Field(
        default_factory=list, description="Per-file changes, largest absolute change first"
    )

    @property
    def install_size_diff(self) -> int:
        """Signed install size delta (head - base) in bytes."""
        return self.head_install_size - self.base_install_size

    @property
    def download_size_diff(self) -> int:
        """Signed download size delta (head - base) in bytes."""
        return self.head_download_size - self.base_download_size

    def to_dict(self) -> Dict[str, object]:
        """Convert to a JSON-serializable dictionary including computed deltas."""
        data = self.model_dump()
        data["install_size_diff"] = self.install_size_diff
        data["download_size_diff"] = self.download_size_diff
        for category, model in zip(data["category_diffs"], self.category_diffs):
            category["size_diff"] = model.size_diff
        for change, model in zip(data["file_changes"], self.file_changes):
            change["size_diff"] = model.size_diff
        return data
