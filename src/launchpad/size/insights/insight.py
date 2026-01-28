from abc import abstractmethod
from dataclasses import dataclass
from typing import Dict, Protocol, Sequence, TypeVar

from launchpad.size.hermes.reporter import HermesReport
from launchpad.size.models.apple import MachOBinaryAnalysis
from launchpad.size.models.common import BaseAppInfo, FileAnalysis

T_co = TypeVar("T_co", covariant=True)


@dataclass
class InsightsInput:
    app_info: BaseAppInfo
    file_analysis: FileAnalysis
    binary_analysis: Sequence[MachOBinaryAnalysis]
    hermes_reports: Dict[str, HermesReport] | None = None


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
