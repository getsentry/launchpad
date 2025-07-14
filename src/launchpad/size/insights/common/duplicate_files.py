from collections import defaultdict
from typing import Dict, List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import DuplicateFilesInsightResult


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    def generate(self, input: InsightsInput) -> DuplicateFilesInsightResult:
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for file in input.file_analysis.files:
            if file.hash_md5:
                files_by_hash[file.hash_md5].append(file)

        duplicate_files: List[FileInfo] = []
        total_savings = 0

        for file_list in files_by_hash.values():
            if len(file_list) > 1:
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
