"""Base classes for app artifact insights."""

from __future__ import annotations

from typing import List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    HermesDebugInfoInsightResult,
)


class HermesDebugInfoInsight(Insight[HermesDebugInfoInsightResult]):
    """Insight for identifying Hermes bytecode files with debug info that can be stripped."""

    def generate(self, input: InsightsInput) -> HermesDebugInfoInsightResult:
        """Generate insight for Hermes bytecode files with debug info.

        Identifies Hermes bytecode files that contain debug info sections
        which could be stripped to reduce file size.
        """
        files_with_debug_info: List[FileInfo] = []
        total_savings = 0

        if not input.hermes_reports:
            return HermesDebugInfoInsightResult(files=[], total_savings=0)

        # Find Hermes files in the file analysis
        for file_info in input.file_analysis.files:
            if file_info.path in input.hermes_reports:
                hermes_report = input.hermes_reports[file_info.path]

                # Check if the debug info section has any content
                debug_info_section = hermes_report["sections"].get("Debug info", {"bytes": 0})
                debug_info_size = debug_info_section.get("bytes", 0)

                if debug_info_size > 0:
                    files_with_debug_info.append(file_info)
                    total_savings += debug_info_size

        files_with_debug_info.sort(
            key=lambda f: input.hermes_reports[f.path]["sections"]["Debug info"]["bytes"]
            if input.hermes_reports
            else 0,
            reverse=True,
        )

        return HermesDebugInfoInsightResult(
            files=files_with_debug_info,
            total_savings=total_savings,
        )
