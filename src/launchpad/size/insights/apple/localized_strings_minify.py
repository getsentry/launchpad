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
    """Analyze potential savings from stripping comments from localized strings files."""

    THRESHOLD_BYTES = 1024

    def __init__(self):
        self._processor = MinifyLocalizedStringsProcessor()

    def generate(self, input: InsightsInput) -> LocalizedStringCommentsInsightResult | None:
        results: list[FileSavingsResult] = []
        total_savings = 0

        for file_info in input.file_analysis.files:
            if not file_info.path.endswith(".strings"):
                continue

            savings = self._calculate_comment_savings(file_info)
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

    def _calculate_comment_savings(self, file_info: FileInfo) -> int:
        try:
            file_path = file_info.full_path
            if not file_path or not file_path.exists():
                logger.error(
                    "Skipping strings minification because file does not exist", extra={"file_path": file_path}
                )
                return 0

            content_bytes = file_path.read_bytes()

            # Binary plists and regular plists have significant overhead
            # Calculate the savings from converting to standard strings format
            if content_bytes.startswith(b"bplist"):
                return self._calculate_plist_to_strings_savings(content_bytes, file_path, "binary plist")

            if content_bytes.startswith(b"<?xml "):
                return self._calculate_plist_to_strings_savings(content_bytes, file_path, "XML plist")

            # For regular strings files, strip comments and normalize whitespace for savings
            content = content_bytes.decode("utf-8", errors="ignore")
            stripped_content = self._processor.strip_string_comments_and_whitespace(content)
            return self._calculate_savings(content.encode("utf-8"), stripped_content.encode("utf-8"))

        except Exception:
            logger.exception("Error calculating localized strings minification savings", extra={"file_path": file_path})
            return 0

    def _calculate_savings(self, original_bytes: bytes, stripped_bytes: bytes) -> int:
        """Calculate savings based on block-aligned size difference."""
        original_size = to_nearest_block_size(len(original_bytes), APPLE_FILESYSTEM_BLOCK_SIZE)
        stripped_size = to_nearest_block_size(len(stripped_bytes), APPLE_FILESYSTEM_BLOCK_SIZE)
        return max(0, original_size - stripped_size)

    def _calculate_plist_to_strings_savings(self, content_bytes: bytes, file_path: Path, plist_type: str) -> int:
        plist_dict = plistlib.loads(content_bytes)
        if isinstance(plist_dict, dict):
            strings_content = self._processor.plist_dict_to_strings(plist_dict)
            strings_bytes = strings_content.encode("utf-8")
            return self._calculate_savings(content_bytes, strings_bytes)

        logger.error(
            "Skipping plist conversion because file is not a valid plist",
            extra={"file_path": file_path, "plist_type": plist_type},
        )
        return 0


class MinifyLocalizedStringsProcessor:
    """Processes localized strings files by stripping comments and normalizing whitespace."""

    # Match /* ... */ block comments or // line comments
    _COMMENT_RE = re.compile(r"/\*.*?\*/|//.*?$", re.S | re.M)
    # Lines that look like:  "key" = "value"; (handles escaped quotes inside strings)
    _KV_RE = re.compile(r'^\s*"(?:[^"\\]|\\.)+"\s*=\s*"(?:[^"\\]|\\.)*"\s*;?\s*$', re.M)

    def plist_dict_to_strings(self, plist_dict: dict[str, str]) -> str:
        """Convert a plist dictionary to standard strings format."""
        lines: list[str] = []
        for key, value in sorted(plist_dict.items()):  # Sort for consistent output
            # Escape quotes and backslashes in key and value
            escaped_key = str(key).replace("\\", "\\\\").replace('"', '\\"')
            escaped_value = str(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'"{escaped_key}"="{escaped_value}";')
        return "\n".join(lines) + "\n" if lines else ""

    def strip_string_comments_and_whitespace(self, content: str) -> str:
        """
        Strip comments and keep only `"key" = "value";` lines, normalizing whitespace to `"key"="value";`.
        NOTE: This is not a full parser; it will break if comment tokens appear inside quoted strings.
        """
        no_comments = self._COMMENT_RE.sub("", content)
        kept: list[str] = []

        for line in self._KV_RE.findall(no_comments):
            key, value = line.split("=", 1)
            # normalize spaces & ensure trailing semicolon
            normalized = f"{key.strip()}={value.strip().rstrip(';')};"
            kept.append(normalized)

        return ("\n".join(kept) + "\n") if kept else ""
