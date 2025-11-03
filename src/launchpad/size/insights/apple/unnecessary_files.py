import re

from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import FileSavingsResult, UnnecessaryFilesInsightResult


class UnnecessaryFilesInsight(Insight[UnnecessaryFilesInsightResult]):
    """Insight for analyzing unnecessary files that are not needed for the app to run."""

    # File patterns that indicate unnecessary files
    UNNECESSARY_FILE_PATTERNS = [
        r"^README",  # README files
        r"^CHANGELOG",  # CHANGELOG files
        r"^AUTHORS",  # AUTHORS files
        r"^CONTRIBUTING",  # CONTRIBUTING files
        r".*\.sh$",  # Shell scripts
        r".*\.bazel$",  # Bazel files
        r".*\.xcconfig$",  # Xcode configuration files
        r".*\.swiftmodule$",  # Swift module files
        r"\.swiftmodule/",  # Files inside .swiftmodule directories
        r"^module\.modulemap$",  # Module map files
        r".*\.bcsymbolmap$",  # Binary symbol map files
        r"^exported_symbols$",  # Exported symbols files
        r".*\.pch$",  # Precompiled header files
        r".*\.xctestplan$",  # Xcode test plan files
    ]

    def __init__(self) -> None:
        """Initialize the insight with compiled regex patterns."""
        self._compiled_patterns = [re.compile(pattern) for pattern in self.UNNECESSARY_FILE_PATTERNS]

    def generate(self, input: InsightsInput) -> UnnecessaryFilesInsightResult | None:
        """Generate insight for unnecessary files.

        Finds all files that match patterns indicating they are not needed
        for the app to run (development files, build artifacts, etc.).
        """
        unnecessary_files: list[FileInfo] = []
        total_size = 0

        for file_info in input.file_analysis.files:
            if self._is_unnecessary_file(file_info):
                unnecessary_files.append(file_info)
                total_size += file_info.size

        if unnecessary_files:
            unnecessary_files.sort(key=lambda f: f.size, reverse=True)
            files = [FileSavingsResult(file_path=file.path, total_savings=file.size) for file in unnecessary_files]

            return UnnecessaryFilesInsightResult(
                files=files,
                total_savings=total_size,
            )

        return None

    def _is_unnecessary_file(self, file_info: FileInfo) -> bool:
        """Check if a file matches patterns for unnecessary files."""
        filename = Path(file_info.path).name

        for pattern in self._compiled_patterns:
            if pattern.search(file_info.path) or pattern.search(filename):
                return True

        return False
