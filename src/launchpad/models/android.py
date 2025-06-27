from pydantic import BaseModel, ConfigDict, Field

from .common import BaseAnalysisResults, BaseAppInfo
from .insights import DuplicateFilesInsightResult, LargeFileInsightResult


class AndroidAppInfo(BaseAppInfo):
    model_config = ConfigDict(frozen=True)
    package_name: str = Field(..., description="Android package name")


class AndroidInsightResults(BaseModel):
    model_config = ConfigDict(frozen=True)

    duplicate_files: DuplicateFilesInsightResult | None = Field(None, description="Duplicate files analysis")
    large_files: LargeFileInsightResult | None = Field(None, description="Large files analysis")


class AndroidAnalysisResults(BaseAnalysisResults):
    model_config = ConfigDict(frozen=True)
    app_info: AndroidAppInfo = Field(..., description="Android app information")
    insights: AndroidInsightResults | None = Field(
        description="Generated insights from the analysis",
    )
