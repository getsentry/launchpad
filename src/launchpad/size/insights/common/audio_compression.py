from __future__ import annotations

import subprocess
import tempfile

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    AudioCompressionInsightResult,
    FileSavingsResult,
)
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class AudioCompressionInsight(Insight[AudioCompressionInsightResult]):
    """Analyze audio compression opportunities in iOS apps.

    Uses ffmpeg to compress audio files to AAC format with 128kbps bitrate for size optimization.
    """

    COMPRESSIBLE_FORMATS = {"wav", "aiff", "aif", "au", "snd", "m4a", "mp3", "caf", "3gp", "3g2", "amr"}

    MIN_SAVINGS_THRESHOLD = 4096

    TARGET_FORMAT = "aac"
    TARGET_BITRATE = 128000

    _MAX_WORKERS = 4

    def generate(self, input: InsightsInput) -> AudioCompressionInsightResult | None:
        """Generate audio compression insights from file analysis."""
        files = [fi for fi in input.file_analysis.files if self._is_compressible_audio_file(fi)]
        if not files:
            return None

        results: list[FileSavingsResult] = []
        with ThreadPoolExecutor(max_workers=min(self._MAX_WORKERS, len(files))) as executor:
            future_to_file = {executor.submit(self._analyze_audio_compression, f): f for f in files}
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    if result and result.total_savings >= self.MIN_SAVINGS_THRESHOLD:
                        results.append(result)
                except Exception as exc:  # pragma: no cover
                    file_info = future_to_file[future]
                    logger.error("Failed to analyze %s: %s", file_info.path, exc)

        if not results:
            return None

        results.sort(key=lambda x: x.total_savings, reverse=True)
        total_savings = sum(f.total_savings for f in results)

        return AudioCompressionInsightResult(
            files=results,
            total_savings=total_savings,
        )

    def _is_compressible_audio_file(self, file_info: FileInfo) -> bool:
        """Check if a file is a compressible audio format."""
        file_type = file_info.file_type.lower()

        if file_type not in self.COMPRESSIBLE_FORMATS:
            return False

        return True

    def _analyze_audio_compression(self, file_info: FileInfo) -> FileSavingsResult | None:
        """Analyze a single audio file for compression opportunities."""
        full_path = file_info.full_path
        if full_path is None:
            logger.debug("Skipping %s because it has no full path", file_info.path)
            return None

        file_size = file_info.size

        try:
            compressed_size = self._get_compressed_size(full_path)
            if compressed_size is None:
                return None

            savings = file_size - compressed_size
            if savings <= 0:
                return None

            return FileSavingsResult(
                file_path=file_info.path,
                total_savings=savings,
            )

        except Exception as exc:
            logger.error("Failed to analyze audio compression for %s: %s", file_info.path, exc)
            return None

    def _get_compressed_size(self, audio_path: Path) -> int | None:
        """Get the compressed size using FFmpeg."""
        with tempfile.NamedTemporaryFile(suffix="-compressed.m4a", delete=True) as temp_file:
            temp_path = Path(temp_file.name)

            try:
                result = subprocess.run(
                    [
                        "ffmpeg",
                        "-i",
                        str(audio_path),
                        "-c:a",
                        self.TARGET_FORMAT,
                        "-b:a",
                        f"{self.TARGET_BITRATE // 1000}k",
                        "-y",  # Overwrite output file
                        str(temp_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    logger.error(
                        "ffmpeg failed for %s: %s",
                        audio_path,
                        result.stderr.strip() if result.stderr else "Unknown error",
                    )
                    return None

                if temp_path.exists():
                    return temp_path.stat().st_size
                else:
                    logger.error("Compressed file not created for %s", audio_path)
                    return None

            except subprocess.TimeoutExpired:
                logger.error("ffmpeg timeout for %s", audio_path)
                return None
            except FileNotFoundError:
                logger.error("ffmpeg not found - audio compression analysis unavailable")
                return None
            except Exception as exc:
                logger.error("Unexpected error during audio compression: %s", exc)
                return None
