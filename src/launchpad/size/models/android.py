from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo, FileInfo
from .insights import (
    DuplicateFilesInsightResult,
    HermesDebugInfoInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
)


class OptimizeableImageFile(BaseModel):
    model_config = ConfigDict(frozen=True)
    file_info: FileInfo = Field(..., description="File info")
    potential_savings: int = Field(..., description="Potential savings")


class WebPOptimizationInsightResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    # list of file paths and their potential savings
    optimizeable_image_files: list[OptimizeableImageFile] = Field(..., description="Optimizeable image files")


class AndroidInsightResults(BaseModel):
    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    webp_optimization: WebPOptimizationInsightResult | None = Field(None, description="WebP optimization analysis")
    large_images: LargeImageFileInsightResult | None = Field(None, description="Large images analysis")
    large_videos: LargeVideoFileInsightResult | None = Field(None, description="Large videos analysis")
    large_audio: LargeAudioFileInsightResult | None = Field(None, description="Large audio files analysis")
    hermes_debug_info: HermesDebugInfoInsightResult | None = Field(None, description="Hermes debug info analysis")


class AndroidAnalysisResults(BaseAnalysisResults):
    model_config = ConfigDict(frozen=True)
    app_info: BaseAppInfo = Field(..., description="Android app information")
    insights: AndroidInsightResults | None = Field(
        description="Generated insights from the analysis",
    )
