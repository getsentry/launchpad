"""Base classes for app bundle insights."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Protocol, TypeVar

from launchpad.models.common import DuplicateFilesInsightResult, FileAnalysis, FileInfo
from launchpad.models.treemap import TreemapResults

from ..models.apple import AppleAppInfo, MachOBinaryAnalysis

T_co = TypeVar("T_co", covariant=True)


@dataclass
class InsightsInput:
    app_info: AppleAppInfo
    file_analysis: FileAnalysis
    treemap: TreemapResults | None
    binary_analysis: List[MachOBinaryAnalysis]


class Insight(Protocol[T_co]):
    """Protocol for insight functions.

    Insights are functions that take analysis results and return typed insight results.
    All data needed for the insight must be collected during the main analysis phase.
    """

    def __call__(self, input: InsightsInput) -> T_co:
        """Generate insights from analysis results.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Typed insight results
        """
        ...


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    """Insight for duplicate files analysis."""

    def __call__(self, input: InsightsInput) -> DuplicateFilesInsightResult:
        """Generate insights about duplicate files.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Duplicate files insight results
        """
        # Group files by hash
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for file in input.file_analysis.files:
            if file.hash_md5:
                files_by_hash[file.hash_md5].append(file)

        # Find all duplicate files
        duplicate_files: List[FileInfo] = []
        total_savings = 0

        for file_list in files_by_hash.values():
            if len(file_list) > 1:
                # Calculate potential savings (all files except one)
                total_file_size = sum(f.size for f in file_list)
                savings = total_file_size - file_list[0].size

                if savings > 0:  # Only include if there are actual savings
                    # Add all files except the first one (which we'll keep)
                    duplicate_files.extend(file_list[1:])
                    total_savings += savings

        return DuplicateFilesInsightResult(
            files=duplicate_files,
            total_savings=total_savings,
        )
