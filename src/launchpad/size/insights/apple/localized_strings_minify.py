import logging
import re

from pathlib import Path

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import LocalizedStringCommentsInsightResult
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import FileSavingsResult
from launchpad.utils.file_utils import to_nearest_block_size

logger = logging.getLogger(__name__)


class MinifyLocalizedStringsProcessor:
    """Remove comments and normalize whitespace in .strings files."""

    # /* ... */ block comments or // line comments
    _COMMENT_RE = re.compile(r"/\*.*?\*/|//.*?$", re.S | re.M)
    # Lines that look like:  "key" = "value";
    _KV_RE = re.compile(r'^\s*"[^"]+"\s*=\s*"[^"]*"\s*;?\s*$', re.M)

    def strip_comments_and_normalize(self, content: str) -> str:
        no_comments = self._COMMENT_RE.sub("", content)
        kept: list[str] = []

        for line in self._KV_RE.findall(no_comments):
            key, value = line.split("=", 1)
            # normalize spaces & ensure trailing semicolon
            normalized = f"{key.strip()}={value.strip().rstrip(';')};"
            kept.append(normalized)

        return ("\n".join(kept) + "\n") if kept else ""


class MinifyLocalizedStringsInsight(Insight[LocalizedStringCommentsInsightResult]):
    """Analyze potential savings from stripping comments from localized strings files."""

    THRESHOLD_BYTES = 1024
    processor = MinifyLocalizedStringsProcessor()

    def generate(self, input: InsightsInput) -> LocalizedStringCommentsInsightResult | None:
        results = [
            FileSavingsResult(file_path=f.path, total_savings=s)
            for f in input.file_analysis.files
            if f.path.endswith(".strings") and (s := self._calculate_comment_savings(f)) > 0
        ]

        total = sum(r.total_savings for r in results)
        if total > self.THRESHOLD_BYTES and results:
            results.sort(key=lambda r: (-r.total_savings, r.file_path))
            return LocalizedStringCommentsInsightResult(files=results, total_savings=total)
        return None

    def _calculate_comment_savings(self, file_info: FileInfo) -> int:
        try:
            p: Path | None = getattr(file_info, "full_path", None)
            if not p or not p.exists():
                return 0

            content = p.read_text(encoding="utf-8", errors="ignore")
            stripped = self.processor.strip_comments_and_normalize(content)

            original_bytes = len(content.encode("utf-8"))
            stripped_bytes = len(stripped.encode("utf-8"))

            original_size = to_nearest_block_size(original_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)
            stripped_size = to_nearest_block_size(stripped_bytes, APPLE_FILESYSTEM_BLOCK_SIZE)

            return max(0, original_size - stripped_size)
        except Exception:
            logger.exception("Error calculating comment savings for %s", file_info.path)
            return 0
