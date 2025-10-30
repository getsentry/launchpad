import logging
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

    # Match /* ... */ block comments or // line comments
    _COMMENT_RE = re.compile(r"/\*.*?\*/|//.*?$", re.S | re.M)
    # Lines that look like:  "key" = "value"; (handles escaped quotes inside strings)
    _KV_RE = re.compile(r'^\s*"(?:[^"\\]|\\.)+"\s*=\s*"(?:[^"\\]|\\.)*"\s*;?\s*$', re.M)

    def generate(self, input: InsightsInput) -> LocalizedStringCommentsInsightResult | None:
        results: list[FileSavingsResult] = []
        total_savings = 0

        for file_info in input.file_analysis.files:
            # TODO(EME-431): look into InfoPlist.strings
            if not file_info.path.endswith(".strings") or file_info.path.endswith("InfoPlist.strings"):
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
        """
        Create a stripped version of the file and compare the block-aligned sizes
        to determine potential savings.
        """
        try:
            file_path = file_info.full_path
            if not file_path or not file_path.exists():
                logger.debug("Skipping strings minification because file does not exist: %s", file_info.path)
                return 0

            content = file_path.read_text(encoding="utf-8", errors="ignore")

            if file_path.startswith("bplist"):
                logger.debug("Skipping strings minification for binary plist: %s", file_info.path)
                return 0

            stripped_content = self.processor.strip_comments_and_normalize(content)

            original_bytes = len(content.encode("utf-8"))
            stripped_bytes = len(stripped_content.encode("utf-8"))

            original_size = to_nearest_block_size(original_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)
            stripped_size = to_nearest_block_size(stripped_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)

            return max(0, original_size - stripped_size)

        except Exception:
            logger.exception("Error calculating comment savings for %s", file_info.path)
            return 0

    def strip_comments_and_normalize(self, content: str) -> str:
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
