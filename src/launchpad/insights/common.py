"""Base classes for app bundle insights."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from launchpad.insights.insight import Insight, InsightsInput
from launchpad.models.common import FileInfo
from launchpad.models.insights import DuplicateFilesInsightResult


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):

    def get_results(self, input: InsightsInput) -> DuplicateFilesInsightResult:
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
