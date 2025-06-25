from abc import abstractmethod
from dataclasses import dataclass
from typing import Protocol, Sequence, TypeVar

from launchpad.models.common import BaseAppInfo, BaseBinaryAnalysis, FileAnalysis
from launchpad.models.treemap import TreemapResults

T_co = TypeVar("T_co", covariant=True)


@dataclass
class InsightsInput:
    app_info: BaseAppInfo
    file_analysis: FileAnalysis
    treemap: TreemapResults | None
    binary_analysis: Sequence[BaseBinaryAnalysis]


class Insight(Protocol[T_co]):
    """Protocol for insight functions.

    Insights are functions that take analysis results and return typed insight results.
    All data needed for the insight must be collected during the main analysis phase.
    """

    @abstractmethod
    def generate(self, input: InsightsInput) -> T_co:
        """Generate insights from analysis results.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Typed insight results
        """
        raise NotImplementedError("Not implemented")
