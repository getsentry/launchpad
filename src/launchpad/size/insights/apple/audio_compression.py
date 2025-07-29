from __future__ import annotations

import logging
import subprocess
import tempfile

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Sequence

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    AudioCompressionInsightResult,
    OptimizableAudioFile,
)
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Silence noisy loggers
logging.getLogger("subprocess").setLevel(logging.WARNING)


class AudioCompressionInsight(Insight[AudioCompressionInsightResult]):
    """Analyze audio compression opportunities in iOS apps.

    Uses afconvert to compress audio files to AAC format with 128kbps bitrate for size optimization.
    """

    # Audio formats that can be compressed
    COMPRESSIBLE_FORMATS = {"wav", "aiff", "aif", "au", "snd", "m4a", "mp3", "caf", "3gp", "3g2", "amr"}

    # Minimum savings threshold (4KB like in image optimization)
    MIN_SAVINGS_THRESHOLD = 4096

    # Target compression settings
    TARGET_FORMAT = "aac"
    TARGET_BITRATE = 128000  # 128 kbps

    _MAX_WORKERS = 4  # Conservative for subprocess-heavy work

    def generate(self, input: InsightsInput) -> AudioCompressionInsightResult | None:
        """Generate audio compression insights from file analysis."""
        files = list(self._iter_compressible_files(input.file_analysis.files))
        if not files:
            return None

        results: list[OptimizableAudioFile] = []
        with ThreadPoolExecutor(max_workers=min(self._MAX_WORKERS, len(files))) as executor:
            future_to_file = {executor.submit(self._analyze_audio_compression, f): f for f in files}
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    if result and result.potential_savings >= self.MIN_SAVINGS_THRESHOLD:
                        results.append(result)
                except Exception as exc:  # pragma: no cover
                    file_info = future_to_file[future]
                    logger.error("Failed to analyze %s: %s", file_info.path, exc)

        if not results:
            return None

        results.sort(key=lambda x: x.potential_savings, reverse=True)
        total_savings = sum(f.potential_savings for f in results)

        return AudioCompressionInsightResult(
            optimizable_files=results,
            total_savings=total_savings,
        )

    def _analyze_audio_compression(self, file_info: FileInfo) -> OptimizableAudioFile | None:
        """Analyze a single audio file for compression opportunities."""
        full_path = file_info.full_path
        if full_path is None:
            logger.debug("Skipping %s because it has no full path", file_info.path)
            return None

        file_size = file_info.size
        file_format = file_info.file_type.lower()

        try:
            compressed_size = self._get_compressed_size(full_path)
            if compressed_size is None:
                return None

            savings = file_size - compressed_size
            if savings <= 0:
                return None

            return OptimizableAudioFile(
                file_path=file_info.path,
                current_size=file_size,
                current_format=file_format,
                compressed_size=compressed_size,
                potential_savings=savings,
                target_format=self.TARGET_FORMAT,
                target_bitrate=self.TARGET_BITRATE,
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
                    timeout=30,
                    check=False,
                )

                if result.returncode != 0:
                    logger.debug(
                        "ffmpeg failed for %s: %s",
                        audio_path,
                        result.stderr.strip() if result.stderr else "Unknown error",
                    )
                    return None

                if temp_path.exists():
                    return temp_path.stat().st_size
                else:
                    logger.debug("Compressed file not created for %s", audio_path)
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

    def _iter_compressible_files(self, files: Sequence[FileInfo]) -> Iterable[FileInfo]:
        """Iterate through files that can be compressed."""
        for fi in files:
            if self._is_compressible_audio_file(fi):
                yield fi

    def _is_compressible_audio_file(self, file_info: FileInfo) -> bool:
        """Check if a file is a compressible audio format."""
        file_type = file_info.file_type.lower()

        # Check if it's a known compressible audio format
        if file_type not in self.COMPRESSIBLE_FORMATS:
            return False

        # Skip files that are already in AAC format to avoid redundant processing
        if file_type in {"aac", "m4a"} and self._is_likely_aac_encoded(file_info):
            return False

        # Skip very small audio files (likely sound effects that shouldn't be compressed)
        if file_info.size < self.MIN_SAVINGS_THRESHOLD * 2:  # At least 8KB
            return False

        return True

    def _is_likely_aac_encoded(self, file_info: FileInfo) -> bool:
        """Heuristic to check if M4A/AAC files are already efficiently encoded."""
        # Simple heuristic: if it's already M4A and reasonably small, assume it's compressed
        # This avoids re-compressing already optimized files
        return file_info.file_type.lower() == "m4a"
