import os
import platform
import shutil
import subprocess
import tempfile

from pathlib import Path
from typing import List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import MachOBinaryAnalysis, StripBinaryFileInfo, StripBinaryInsightResult
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class StripSymbolsInsight(Insight[StripBinaryInsightResult]):
    """Insight for analyzing potential savings from stripping Mach-O binaries.

    This insight identifies how much space could be saved by stripping debug symbols
    and other unnecessary data from Mach-O binaries, matching the Swift BundleAnalyzer.
    """

    MIN_STRIPPED_SAVINGS = 2 * 1024  # 2KB

    def generate(self, insights_input: InsightsInput) -> StripBinaryInsightResult | None:
        strip_files: List[StripBinaryFileInfo] = []
        total_savings = 0

        for binary_analysis in insights_input.binary_analysis:
            if not isinstance(binary_analysis, MachOBinaryAnalysis):
                continue
            binary_path = Path(binary_analysis.binary_path)
            if "Watch" in str(binary_path) or "watch" in str(binary_path).lower():
                logger.debug(f"Skipping Watch app binary: {binary_path}")
                continue
            try:
                savings = self._calculate_actual_strip_savings(binary_path)
            except Exception as e:
                logger.warning(f"Failed to calculate strip savings for {binary_path}: {e}")
                continue
            if savings > self.MIN_STRIPPED_SAVINGS:
                strip_file_info = StripBinaryFileInfo(
                    macho_binary=binary_analysis,
                    size_saved=savings,
                )
                strip_files.append(strip_file_info)
                total_savings += savings
                logger.debug(f"Found strip savings for {binary_path}: {savings} bytes")
        if strip_files:
            return StripBinaryInsightResult(
                files=strip_files,
                total_savings=total_savings,
            )
        return None

    def _calculate_actual_strip_savings(self, binary_path: Path) -> int:
        """Actually strip a temp copy of the binary and return the size savings, using correct flags."""
        orig_size = os.stat(binary_path).st_size
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            shutil.copy2(binary_path, tmp_path)
            is_dylib = binary_path.suffix == ".dylib"

            # Use llvm-strip on Linux, strip on Darwin
            strip_tool = "llvm-strip" if platform.system() == "Linux" else "strip"

            if is_dylib:
                if strip_tool == "llvm-strip":
                    strip_cmd = [strip_tool, "-rSTx", tmp_path]
                else:
                    strip_cmd = [strip_tool, "-rSTx", "-no_code_signature_warning", tmp_path]
            else:
                if strip_tool == "llvm-strip":
                    strip_cmd = [strip_tool, "-STx", tmp_path]
                else:
                    strip_cmd = [strip_tool, "-STx", "-no_code_signature_warning", tmp_path]
            result = subprocess.run(strip_cmd, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"{strip_tool} failed: {result.stderr.decode().strip()}")
            stripped_size = os.stat(tmp_path).st_size
            savings = orig_size - stripped_size
            return savings if savings > 0 else 0
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
