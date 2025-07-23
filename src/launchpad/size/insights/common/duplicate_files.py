import os

from collections import defaultdict
from typing import Dict, List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import DuplicateFileGroup, DuplicateFilesInsightResult


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    def generate(self, input: InsightsInput) -> DuplicateFilesInsightResult:
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for file in input.file_analysis.files:
            if file.hash_md5:
                files_by_hash[file.hash_md5].append(file)

        groups: List[DuplicateFileGroup] = []
        total_savings = 0

        for file_list in files_by_hash.values():
            if len(file_list) > 1:
                # Calculate savings: total size - size of one copy we keep
                total_file_size = sum(f.size for f in file_list)
                savings_for_this_group = total_file_size - file_list[0].size

                if savings_for_this_group > 0:  # Only include if there are actual savings
                    sorted_files = sorted(file_list, key=lambda f: (-f.size, f.path))
                    filenames = sorted(set(os.path.basename(f.path) for f in sorted_files))
                    group_filename = filenames[0]

                    group = DuplicateFileGroup(
                        filename=group_filename,
                        files=sorted_files,
                        total_savings=savings_for_this_group,
                    )
                    groups.append(group)
                    total_savings += savings_for_this_group

        groups = sorted(groups, key=lambda g: (-g.total_savings, g.filename))

        return DuplicateFilesInsightResult(
            groups=groups,
            total_savings=total_savings,
        )
