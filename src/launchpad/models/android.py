from pydantic import ConfigDict, Field

from launchpad.models.treemap import TreemapResults

from .common import BaseAnalysisResults, BaseAppInfo


class AndroidAppInfo(BaseAppInfo):

    model_config = ConfigDict(frozen=True)
    package_name: str = Field(..., description="Android package name")


class AndroidAnalysisResults(BaseAnalysisResults):
    """Complete Android analysis results."""

    model_config = ConfigDict(frozen=True)
    app_info: AndroidAppInfo = Field(..., description="Android app information")
    treemap_results: TreemapResults = Field(..., description="Hierarchical size analysis treemap")
