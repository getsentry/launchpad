from abc import abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, TypeVar

from launchpad.size.hermes.reporter import HermesReport
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.common import AppComponent, BaseAppInfo, FileAnalysis

T_co = TypeVar("T_co", covariant=True)


@dataclass
class InsightsInput:
    app_info: BaseAppInfo
    file_analysis: FileAnalysis
    binary_analysis: Sequence[MachOBinaryAnalysis]
    hermes_reports: dict[str, HermesReport] | None = None
    app_components: Sequence[AppComponent] = ()


class Insight(Protocol[T_co]):
    """Protocol for insight functions.

    Insights are functions that take analysis results and return typed insight results.
    All data needed for the insight must be collected during the main analysis phase.
    """

    @abstractmethod
    def generate(self, input: InsightsInput) -> T_co | None:
        """Generate insights from analysis results.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Typed insight results
        """
        raise NotImplementedError("Not implemented")
