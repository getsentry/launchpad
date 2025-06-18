from typing import List

from pydantic import BaseModel, ConfigDict, Field

from launchpad.models.common import FileInfo


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
