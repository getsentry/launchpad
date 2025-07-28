from typing import List

from pydantic import BaseModel, ConfigDict, Field

from launchpad.size.models.common import FileInfo


class BaseInsightResult(BaseModel):
    """Base class for all insight results."""

    model_config = ConfigDict(frozen=True)

    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes")


class FileSavingsResult(BaseModel):
    """File savings information."""

    model_config = ConfigDict(frozen=True)

    file_path: str = Field(..., description="Path to the file within the app bundle")
    total_savings: int = Field(..., ge=0, description="Potential size savings or file size in bytes")


class FileSavingsResultGroup(BaseModel):
    """Group of files with savings information."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Group name or identifier")
    files: List[FileSavingsResult] = Field(..., description="Files in this group")
    total_savings: int = Field(..., ge=0, description="Total savings for this group")


class DuplicateFilesInsightResult(BaseInsightResult):
    """Results from duplicate files analysis."""

    groups: List[FileSavingsResultGroup] = Field(..., description="Groups of duplicate files by filename")

    @property
    def duplicate_count(self) -> int:
        """Total number of duplicate files across all groups."""
        return sum(len(group.files) - 1 for group in self.groups)

    @property
    def total_files(self) -> int:
        """Total number of files across all groups."""
        return sum(len(group.files) for group in self.groups)


class LargeImageFileInsightResult(BaseInsightResult):
    """Results from large image files analysis."""

    files: List[FileSavingsResult] = Field(..., description="Image files larger than 10MB with their sizes")


class LargeVideoFileInsightResult(BaseInsightResult):
    """Results from large video files analysis."""

    files: List[FileSavingsResult] = Field(..., description="Video files larger than 10MB with their sizes")


class LargeAudioFileInsightResult(BaseInsightResult):
    """Results from large audio files analysis."""

    files: List[FileSavingsResult] = Field(..., description="Audio files larger than 5MB with their sizes")


class HermesDebugInfoInsightResult(BaseInsightResult):
    """Results from Hermes debug info analysis."""

    files: List[FileSavingsResult] = Field(..., description="Hermes bytecode files with potential debug info savings")


class UnnecessaryFilesInsightResult(BaseInsightResult):
    """Results from unnecessary files analysis."""

    files: List[FileSavingsResult] = Field(..., description="Unnecessary files with their sizes that could be removed")


class OptimizeableImageFile(BaseModel):
    model_config = ConfigDict(frozen=True)
    file_info: FileInfo = Field(..., description="File info")
    potential_savings: int = Field(..., description="Potential savings")


class WebPOptimizationInsightResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    # list of file paths and their potential savings
    optimizeable_image_files: list[OptimizeableImageFile] = Field(..., description="Optimizeable image files")


class LocalizedStringInsightResult(BaseInsightResult):
    """Results from localized string analysis."""

    files: List[FileSavingsResult] = Field(
        ..., description="Localized strings files exceeding 100KB threshold with their sizes"
    )


class LocalizedStringCommentsInsightResult(BaseInsightResult):
    """Results from localized string comments analysis."""

    files: List[FileSavingsResult] = Field(
        ..., description="Localized strings files with comment stripping opportunities"
    )


class SmallFilesInsightResult(BaseInsightResult):
    """Results from small files analysis."""

    files: List[FileSavingsResult] = Field(..., description="Files smaller than filesystem block size with their sizes")


class LooseImagesInsightResult(BaseInsightResult):
    """Results from loose images analysis."""

    groups: List[FileSavingsResultGroup] = Field(
        ..., description="Groups of loose images that could be moved to asset catalogs"
    )


class MainBinaryExportMetadataResult(BaseInsightResult):
    """Results from main binary exported symbols metadata analysis."""

    files: List[FileSavingsResult] = Field(..., description="Main binaries with export metadata that could be reduced")


class OptimizableImageFile(BaseModel):
    """Information about an image file that can be optimized."""

    model_config = ConfigDict(frozen=True)

    file_path: str = Field(..., description="File path")
    current_size: int = Field(..., description="Current file size in bytes")

    # Minification savings (optimizing current format)
    minify_savings: int = Field(default=0, ge=0, description="Potential savings from minification")
    minified_size: int | None = Field(default=None, description="Size after minification")

    # HEIC conversion savings (converting to HEIC format)
    conversion_savings: int = Field(default=0, ge=0, description="Potential savings from HEIC conversion")
    heic_size: int | None = Field(default=None, description="Size after HEIC conversion")

    @property
    def potential_savings(self) -> int:
        """Calculate total potential savings from the best optimization."""
        return max(self.minify_savings, self.conversion_savings)

    @property
    def best_optimization_type(self) -> str:
        """Return the optimization type that provides the most savings."""
        if self.conversion_savings > self.minify_savings:
            return "convert_to_heic"
        elif self.minify_savings > 0:
            return "minify"
        else:
            return "none"


class ImageOptimizationInsightResult(BaseInsightResult):
    """Results from image optimization analysis."""

    optimizable_files: List[OptimizableImageFile] = Field(
        ..., description="Files that can be optimized with potential savings"
    )


class StripBinaryFileInfo(BaseModel):
    """Savings information from stripping a Mach-O binary."""

    file_path: str = Field(..., description="Path to the binary file within the app bundle")
    debug_sections_savings: int = Field(..., ge=0, description="Savings from removing debug sections")
    symbol_table_savings: int = Field(..., ge=0, description="Savings from removing symbol table")
    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes from stripping debug content")


class StripBinaryInsightResult(BaseInsightResult):
    """Results from strip binary analysis."""

    files: List[StripBinaryFileInfo] = Field(..., description="Files that could save size by stripping the binary")
    total_debug_sections_savings: int = Field(..., ge=0, description="Total potential savings from debug sections")
    total_symbol_table_savings: int = Field(..., ge=0, description="Total potential savings from symbol tables")
