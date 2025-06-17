"""Base classes for app bundle insights."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Protocol, TypeVar

from pydantic import BaseModel

from launchpad.models.common import DuplicateFileGroup, FileInfo

from ..models.apple import AppleAnalysisResults

T = TypeVar("T", bound=BaseModel)


class Insight(Protocol):
    """Protocol for insight functions.

    Insights are functions that take analysis results and return a dictionary of insights.
    All data needed for the insight must be collected during the main analysis phase.
    """

    def __call__(self, results: AppleAnalysisResults) -> Dict[str, Any]:
        """Generate insights from analysis results.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Dictionary containing the insight data
        """
        ...


class DuplicateFilesInsight:
    """Insight for duplicate files analysis."""

    def generate_insight(self, results: AppleAnalysisResults) -> Dict[str, Any]:
        """Generate insights about duplicate files.

        Args:
            results: The analysis results to generate insights from

        Returns:
            Dictionary containing duplicate file insights
        """
        # Group files by hash
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for file in results.file_analysis.files:
            if file.hash_md5:
                files_by_hash[file.hash_md5].append(file)

        # Find duplicate groups (files with same hash)
        duplicate_groups = []
        for file_list in files_by_hash.values():
            if len(file_list) > 1:
                # Calculate potential savings (all files except one)
                total_file_size = sum(f.size for f in file_list)
                savings = total_file_size - file_list[0].size

                if savings > 0:  # Only include if there are actual savings
                    duplicate_groups.append(
                        DuplicateFileGroup(
                            files=file_list,
                            potential_savings=savings,
                        )
                    )

        if not duplicate_groups:
            return {
                "has_duplicates": False,
                "total_savings": 0,
                "duplicate_groups": [],
            }

        # Sort groups by potential savings
        sorted_groups = sorted(duplicate_groups, key=lambda g: g.potential_savings, reverse=True)
        total_savings = sum(group.potential_savings for group in duplicate_groups)

        return {
            "has_duplicates": True,
            "total_savings": total_savings,
            "duplicate_groups": [
                {
                    "files": [f.path for f in group.files],
                    "size": group.files[0].size,
                    "potential_savings": group.potential_savings,
                }
                for group in sorted_groups
            ],
        }
