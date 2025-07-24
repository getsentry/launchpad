import logging

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import LocalizedStringCommentsInsightResult
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import FileSavingsResult
from launchpad.utils.file_utils import to_nearest_block_size

logger = logging.getLogger(__name__)


class MinifyLocalizedStringsProcessor:
    """Processor for cleaning up localized strings files by removing comments and normalizing whitespace."""

    def strip_comments_and_normalize(self, content: str) -> str:
        """Strip comments from strings file content while preserving key-value pairs.

        This handles both /* */ block comments and // line comments,
        and also normalizes whitespace around = assignments for additional savings.
        """
        lines = content.split("\n")
        result_lines: list[str] = []

        in_block_comment = False

        for line in lines:
            stripped_line = line.strip()

            # Skip empty lines
            if not stripped_line:
                continue

            # Handle block comments
            if in_block_comment:
                if "*/" in line:
                    # End of block comment, keep anything after */
                    after_comment = line.split("*/", 1)[1] if "*/" in line else ""
                    in_block_comment = False
                    if after_comment.strip():
                        stripped_line = after_comment.strip()
                    else:
                        continue
                else:
                    # Still in block comment, skip this line
                    continue

            # Check for start of block comment
            if "/*" in stripped_line:
                before_comment = stripped_line.split("/*", 1)[0]
                if "*/" in stripped_line:
                    # Single line block comment
                    after_comment = stripped_line.split("*/", 1)[1] if "*/" in stripped_line else ""
                    stripped_line = (before_comment + after_comment).strip()
                else:
                    # Multi-line block comment starts
                    in_block_comment = True
                    stripped_line = before_comment.strip()

            # Remove line comments
            if "//" in stripped_line:
                stripped_line = stripped_line.split("//", 1)[0].strip()

            # Only keep lines that look like key-value pairs or are non-empty
            if stripped_line and ("=" in stripped_line or stripped_line.startswith('"')):
                # Normalize whitespace around = for additional savings: "key" = "value" -> "key"="value"
                if "=" in stripped_line and stripped_line.count('"') >= 4:
                    # This looks like a key-value pair, normalize the spacing
                    parts = stripped_line.split("=", 1)
                    if len(parts) == 2:
                        key_part = parts[0].strip()
                        value_part = parts[1].strip()
                        stripped_line = f"{key_part}={value_part}"

                result_lines.append(stripped_line)

        return "\n".join(result_lines) + "\n" if result_lines else ""


class MinifyLocalizedStringsInsight(Insight[LocalizedStringCommentsInsightResult]):
    """Insight for analyzing potential savings from stripping comments from localized strings files."""

    THRESHOLD_BYTES = 1024

    def __init__(self):
        self.processor = MinifyLocalizedStringsProcessor()

    def generate(self, input: InsightsInput) -> LocalizedStringCommentsInsightResult | None:
        """Generate insight for localized strings comment stripping opportunities.

        Finds all Localizable.strings files,
        analyzes potential savings from removing comments, and returns insight if above threshold.
        """
        comment_savings: list[FileSavingsResult] = []
        total_savings = 0

        # Find all Localizable.strings and InfoPlist.strings files in *.lproj directories
        for file_info in input.file_analysis.files:
            if file_info.path.endswith(".strings"):
                savings = self._calculate_comment_savings(file_info)
                if savings > 0:
                    comment_savings.append(FileSavingsResult(file_path=file_info.path, total_savings=savings))
                    total_savings += savings

        if total_savings > self.THRESHOLD_BYTES and len(comment_savings) > 0:
            comment_savings.sort(key=lambda x: (-x.total_savings, x.file_path))
            return LocalizedStringCommentsInsightResult(
                files=comment_savings,
                total_savings=total_savings,
            )

        return None

    def _calculate_comment_savings(self, file_info: FileInfo) -> int:
        """Calculate potential savings from removing comments from a strings file.

        This simulates what the Swift code did: create a stripped version of the file
        and compare the sizes to determine potential savings.
        """
        try:
            file_path = file_info.full_path
            if not file_path or not file_path.exists():
                return 0

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Create stripped version (remove comments but keep key-value pairs)
            stripped_content = self.processor.strip_comments_and_normalize(content)

            # Calculate size difference using filesystem block sizes
            original_bytes = len(content.encode("utf-8"))
            stripped_bytes = len(stripped_content.encode("utf-8"))

            original_size = to_nearest_block_size(original_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)
            stripped_size = to_nearest_block_size(stripped_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)

            return max(0, original_size - stripped_size)

        except Exception as e:
            logger.error(f"Error calculating comment savings for {file_info.path}: {e}")
            return 0
