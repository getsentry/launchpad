from typing import List, Tuple

from pydantic import BaseModel, ConfigDict, Field


class BaseInsightResult(BaseModel):
    """Base class for all insight results."""

    model_config = ConfigDict(frozen=True)

    total_savings: int = Field(..., ge=0, description="Total potential savings in bytes")

    def get_file_paths(self) -> List[str]:
        """Return file paths flagged by this insight. Override in subclasses."""
        return []

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        """Return (file_path, savings) pairs. Override in subclasses."""
        return []


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


class FilesInsightResult(BaseInsightResult):
    """Base class for insights that return a list of files with savings."""

    files: List[FileSavingsResult] = Field(..., description="Files with potential savings")

    def get_file_paths(self) -> List[str]:
        return [f.file_path for f in self.files]

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        return [(f.file_path, f.total_savings) for f in self.files]


class GroupsInsightResult(BaseInsightResult):
    """Base class for insights that return grouped file results."""

    groups: List[FileSavingsResultGroup] = Field(..., description="Groups of files with savings information")

    def get_file_paths(self) -> List[str]:
        return [f.file_path for group in self.groups for f in group.files]

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        return [(f.file_path, f.total_savings) for group in self.groups for f in group.files]


class DuplicateFilesInsightResult(GroupsInsightResult):
    """Results from duplicate files analysis.

    Groups contain duplicate files organized by filename.
    """

    pass


class LargeImageFileInsightResult(FilesInsightResult):
    """Results from large image files analysis.

    Files contain image files larger than 10MB with their sizes.
    """

    pass


class LargeVideoFileInsightResult(FilesInsightResult):
    """Results from large video files analysis.

    Files contain video files larger than 10MB with their sizes.
    """

    pass


class LargeAudioFileInsightResult(FilesInsightResult):
    """Results from large audio files analysis.

    Files contain audio files larger than 5MB with their sizes.
    """

    pass


class HermesDebugInfoInsightResult(FilesInsightResult):
    """Results from Hermes debug info analysis.

    Files contain Hermes bytecode files with potential debug info savings.
    """

    pass


class UnnecessaryFilesInsightResult(FilesInsightResult):
    """Results from unnecessary files analysis.

    Files contain unnecessary files with their sizes that could be removed.
    """

    pass


class WebPOptimizationInsightResult(FilesInsightResult):
    """Results from WebP optimization analysis.

    Files contain optimizeable image files.
    """

    pass


class LocalizedStringInsightResult(BaseInsightResult):
    """Results from localized string analysis.

    Reports the total estimated savings that could be achieved by optimizing localized strings.

    """

    pass


class LocalizedStringCommentsInsightResult(FilesInsightResult):
    """Results from localized string comments analysis.

    Files contain localized strings files with comment stripping opportunities.
    """

    pass


class SmallFilesInsightResult(FilesInsightResult):
    """Results from small files analysis.

    Files contain files smaller than filesystem block size with their sizes.
    """

    pass


class LooseImagesInsightResult(GroupsInsightResult):
    """Results from loose images analysis.

    Groups contain loose images that could be moved to asset catalogs.
    """

    pass


class MainBinaryExportMetadataResult(FilesInsightResult):
    """Results from main binary exported symbols metadata analysis.

    Files contain main binaries with export metadata that could be reduced.
    """

    pass


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

    # Asset catalog specific fields
    idiom: str | None = Field(default=None, description="Device idiom for asset catalog images")
    colorspace: str | None = Field(default=None, description="Color space for asset catalog images")

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

    def get_file_paths(self) -> List[str]:
        return [f.file_path for f in self.optimizable_files]

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        return [(f.file_path, f.potential_savings) for f in self.optimizable_files]


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

    def get_file_paths(self) -> List[str]:
        return [f.file_path for f in self.files]

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        return [(f.file_path, f.total_savings) for f in self.files]


class AudioCompressionInsightResult(FilesInsightResult):
    """Results from audio compression analysis.

    Files contain audio files that can be compressed with their potential savings.
    """

    pass


class VideoCompressionFileSavingsResult(FileSavingsResult):
    """Information about a video file that can be compressed."""

    recommended_codec: str = Field(..., description="Recommended codec (h264 or hevc)")


class VideoCompressionInsightResult(BaseInsightResult):
    """Results from video compression analysis.

    Files contain video files that can be compressed with their potential savings.
    """

    files: List[VideoCompressionFileSavingsResult] = Field(..., description="Video files that can be compressed")

    def get_file_paths(self) -> List[str]:
        return [f.file_path for f in self.files]

    def get_file_path_savings(self) -> List[Tuple[str, int]]:
        return [(f.file_path, f.total_savings) for f in self.files]


class MultipleNativeLibraryArchInsightResult(FilesInsightResult):
    """Results from multiple native library architectures analysis.

    Files contain native library files for non-arm64-v8a architectures that could be removed.
    """

    pass
