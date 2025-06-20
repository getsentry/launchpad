from dataclasses import dataclass
from typing import Protocol, TypeVar

from ..models.apple import AppleAppInfo, MachOBinaryAnalysis
from ..models.common import FileAnalysis
from ..models.treemap import TreemapResults

T_co = TypeVar("T_co", covariant=True)


@dataclass
class InsightsInput:
    app_info: AppleAppInfo
    file_analysis: FileAnalysis
    treemap: TreemapResults | None
    binary_analysis: list[MachOBinaryAnalysis]


class Insight(Protocol[T_co]):
    """Protocol for insight functions.

    Insights are functions that take analysis results and return typed insight results.
    All data needed for the insight must be collected during the main analysis phase.
    """

    def get_results(self, input: InsightsInput) -> T_co:
        """Generate insights from analysis results.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Typed insight results
        """
        raise NotImplementedError("Not implemented")
