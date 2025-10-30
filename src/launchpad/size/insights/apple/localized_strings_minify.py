import logging
import plistlib
import re

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

            # Binary plist files don't support comments, so we can skip them
            if content_bytes.startswith(b"bplist"):
                logger.debug("Skipping strings minification for binary plist: %s", file_info.path)
                return 0

            # Try to parse as plist (XML format) if it looks like XML
            if content_bytes.startswith(b"<?xml "):
                try:
                    # Strip XML comments before parsing
                    content_str = content_bytes.decode("utf-8", errors="ignore")
                    content_no_comments = self._processor.strip_xml_comments(content_str)
                    stripped_content_bytes = content_no_comments.encode("utf-8")

                    # Parse and re-serialize to normalize formatting
                    plist_dict = plistlib.loads(stripped_content_bytes)
                    if isinstance(plist_dict, dict):
                        stripped_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
                        return self._calculate_savings(content_bytes, stripped_bytes)
                except Exception:
                    # Not a valid plist, fall through to treat as text format
                    logger.error(
                        "Skipping strings minification because file is not a valid plist",
                        extra={"file_path": file_path},
                    )
                    pass

            # Treat as text format (traditional .strings format)
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


class MinifyLocalizedStringsProcessor:
    """Processes localized strings files by stripping comments and normalizing whitespace."""

    # Match /* ... */ block comments or // line comments
    _COMMENT_RE = re.compile(r"/\*.*?\*/|//.*?$", re.S | re.M)
    # Match XML comments <!-- ... -->
    _XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
    # Lines that look like:  "key" = "value"; (handles escaped quotes inside strings)
    _KV_RE = re.compile(r'^\s*"(?:[^"\\]|\\.)+"\s*=\s*"(?:[^"\\]|\\.)*"\s*;?\s*$', re.M)

    def strip_xml_comments(self, content: str) -> str:
        """Strip XML-style comments (<!-- ... -->) from content."""
        return self._XML_COMMENT_RE.sub("", content)

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
