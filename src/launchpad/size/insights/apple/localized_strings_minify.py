import logging
import plistlib
import re

from pathlib import Path

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import FileSavingsResult, LocalizedStringCommentsInsightResult
from launchpad.utils.file_utils import to_nearest_block_size

logger = logging.getLogger(__name__)


class MinifyLocalizedStringsInsight(Insight[LocalizedStringCommentsInsightResult]):
    """Analyze potential savings from converting localized strings files to binary plist format."""

    THRESHOLD_BYTES = 1024

    def __init__(self):
        self._processor = MinifyLocalizedStringsProcessor()

    def generate(self, input: InsightsInput) -> LocalizedStringCommentsInsightResult | None:
        results: list[FileSavingsResult] = []
        total_savings = 0

        for file_info in input.file_analysis.files:
            if not file_info.path.endswith(".strings"):
                continue

            savings = self._calculate_binary_plist_savings(file_info)
            if savings > 0:
                result = FileSavingsResult(
                    file_path=str(file_info.path),
                    total_savings=int(savings),
                )
                results.append(result)
                total_savings += result.total_savings

        if total_savings > self.THRESHOLD_BYTES and results:
            results.sort(key=lambda x: (-x.total_savings, x.file_path))
            return LocalizedStringCommentsInsightResult(
                files=results,
                total_savings=total_savings,
            )

        return None

    def _calculate_binary_plist_savings(self, file_info: FileInfo) -> int:
        """Calculate savings from converting strings files to binary plist format."""
        try:
            file_path = file_info.full_path
            if not file_path or not file_path.exists():
                logger.error("Skipping strings conversion because file does not exist", extra={"file_path": file_path})
                return 0

            content_bytes = file_path.read_bytes()

            # Binary plists are already optimal and don't support comments
            # You can get slightly smaller size by converting to strings format, but it's not worth the effort
            # and there are other benefits to keeping them in binary format.
            if content_bytes.startswith(b"bplist"):
                return 0

            # XML plists: convert to binary plist (Xcode standard)
            if content_bytes.startswith(b"<?xml "):
                return self._calculate_xml_to_binary_plist_savings(content_bytes, file_path)

            # Legacy strings files: parse and convert to binary plist
            return self._calculate_strings_to_binary_plist_savings(content_bytes, file_path)

        except Exception:
            logger.exception("Error calculating binary plist conversion savings", extra={"file_path": file_path})
            return 0

    def _calculate_savings(self, original_bytes: bytes, converted_bytes: bytes) -> int:
        """Calculate savings based on block-aligned size difference."""
        original_size = to_nearest_block_size(len(original_bytes), APPLE_FILESYSTEM_BLOCK_SIZE)
        converted_size = to_nearest_block_size(len(converted_bytes), APPLE_FILESYSTEM_BLOCK_SIZE)
        return max(0, original_size - converted_size)

    def _calculate_xml_to_binary_plist_savings(self, content_bytes: bytes, file_path: Path) -> int:
        """Calculate savings from converting XML plist to binary plist format."""
        plist_dict = plistlib.loads(content_bytes)
        if not isinstance(plist_dict, dict):
            logger.error(
                "Skipping plist conversion because file is not a valid plist dict",
                extra={"file_path": file_path, "plist_type": "XML plist"},
            )
            return 0

        binary_plist_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
        return self._calculate_savings(content_bytes, binary_plist_bytes)

    def _calculate_strings_to_binary_plist_savings(self, content_bytes: bytes, file_path: Path) -> int:
        """Calculate savings from converting regular strings file to binary plist format."""
        content = content_bytes.decode("utf-8", errors="ignore")
        plist_dict = self._processor.parse_strings_file(content)

        if not plist_dict:
            return 0

        binary_plist_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
        return self._calculate_savings(content_bytes, binary_plist_bytes)


class MinifyLocalizedStringsProcessor:
    """Parser for .strings files to extract key-value pairs for binary plist conversion."""

    # Regex to match key-value pairs: "key" = "value"; (handles escaped quotes)
    _KV_RE = re.compile(r'^\s*"(?:[^"\\]|\\.)+"\s*=\s*"(?:[^"\\]|\\.)*"\s*;?\s*$', re.M)
    # Regex to strip comments (/* ... */ and // ...)
    _COMMENT_RE = re.compile(r"/\*.*?\*/|//.*?$", re.S | re.M)

    def parse_strings_file(self, content: str) -> dict[str, str] | None:
        """
        Parse a .strings file and return a dictionary of key-value pairs.
        Returns None if the file is empty or has no valid key-value pairs.
        """
        # Strip comments first to avoid false matches
        no_comments = self._COMMENT_RE.sub("", content)

        result: dict[str, str] = {}

        for line in self._KV_RE.findall(no_comments):
            parts = line.split("=", 1)
            if len(parts) != 2:
                continue

            key_part = parts[0].strip()
            value_part = parts[1].strip().rstrip(";").strip()

            # Remove surrounding quotes
            if key_part.startswith('"') and key_part.endswith('"'):
                key_part = key_part[1:-1]
            if value_part.startswith('"') and value_part.endswith('"'):
                value_part = value_part[1:-1]

            # Unescape quotes and backslashes
            key = key_part.replace('\\"', '"').replace("\\\\", "\\")
            value = value_part.replace('\\"', '"').replace("\\\\", "\\")

            result[key] = value

        return result if result else None
