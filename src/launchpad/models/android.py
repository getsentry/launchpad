from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo
from .insights import DuplicateFilesInsightResult, ImageOptimizationInsightResult


class AndroidAppInfo(BaseAppInfo):
    model_config = ConfigDict(frozen=True)
    package_name: str = Field(..., description="Android package name")


class AndroidInsightResults(BaseModel):
    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    image_optimization: ImageOptimizationInsightResult | None = Field(None, description="WebP Optimization analysis")


class AndroidAnalysisResults(BaseAnalysisResults):
    model_config = ConfigDict(frozen=True)
    app_info: AndroidAppInfo = Field(..., description="Android app information")
    insights: AndroidInsightResults | None = Field(
        description="Generated insights from the analysis",
    )
