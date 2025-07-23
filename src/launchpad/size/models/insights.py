from typing import List

from pydantic import BaseModel, ConfigDict, Field

from .common import FileInfo


class BaseInsightResult(BaseModel):
    """Base class for all insight results."""

    model_config = ConfigDict(frozen=True)

    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes")


class DuplicateFileGroup(BaseModel):
    """Group of duplicate files with the same filename."""

    model_config = ConfigDict(frozen=True)

    filename: str = Field(..., description="The filename (without path)")
    files: List[FileInfo] = Field(..., description="All duplicate files with this filename")
    total_savings: int = Field(..., ge=0, description="Total savings for this filename group")

    @property
    def duplicate_count(self) -> int:
        """Number of duplicate files (excluding the original)."""
        return len(self.files) - 1


class DuplicateFilesInsightResult(BaseInsightResult):
    """Results from duplicate files analysis."""

    groups: List[DuplicateFileGroup] = Field(..., description="Groups of duplicate files by filename")

    @property
    def duplicate_count(self) -> int:
        """Total number of duplicate files across all groups."""
        return sum(group.duplicate_count for group in self.groups)

    @property
    def total_files(self) -> int:
        """Total number of files across all groups."""
        return sum(len(group.files) for group in self.groups)


class LargeImageFileInsightResult(BaseInsightResult):
    """Results from large image files analysis."""

    files: List[FileInfo] = Field(..., description="Image files larger than 10MB")


class LargeVideoFileInsightResult(BaseInsightResult):
    """Results from large video files analysis."""

    files: List[FileInfo] = Field(..., description="Video files larger than 10MB")


class LargeAudioFileInsightResult(BaseInsightResult):
    """Results from large audio files analysis."""

    files: List[FileInfo] = Field(..., description="Audio files larger than 5MB")


class HermesDebugInfoInsightResult(BaseInsightResult):
    """Results from Hermes debug info analysis."""

    files: List[FileInfo] = Field(..., description="Hermes bytecode files with debug info")


class UnnecessaryFilesInsightResult(BaseInsightResult):
    """Results from unnecessary files analysis."""

    files: List[FileInfo] = Field(..., description="Unnecessary files that are not needed for the app to run")
