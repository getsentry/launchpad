from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field

from .common import FileInfo


class BaseInsightResult(BaseModel):
    """Base class for all insight results."""

    model_config = ConfigDict(frozen=True)

    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes")


class DuplicateFilesInsightResult(BaseInsightResult):
    """Results from duplicate files analysis."""

    files: List[FileInfo] = Field(..., description="Files in the group")

    @property
    def duplicate_count(self) -> int:
        """Number of duplicate files (excluding the original)."""
        return len(self.files) - 1


class WebpAssetInsightResult(BaseInsightResult):
    """Results from WebP asset optimization analysis."""

    optimization_opportunities: List[Dict[str, Any]] = Field(
        ..., description="List of image files that could be optimized with WebP"
    )
    total_potential_savings: int = Field(
        ..., ge=0, description="Total potential savings in bytes from WebP optimization"
    )
