from typing import List

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


class LargeImageFileInsightResult(BaseInsightResult):
    """Results from large image files analysis."""

    files: List[FileInfo] = Field(..., description="Image files larger than 10MB")


class LargeVideoFileInsightResult(BaseInsightResult):
    """Results from large video files analysis."""

    files: List[FileInfo] = Field(..., description="Video files larger than 10MB")


class LargeAudioFileInsightResult(BaseInsightResult):
    """Results from large audio files analysis."""

    files: List[FileInfo] = Field(..., description="Audio files larger than 5MB")
