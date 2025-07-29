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
    OptimizableVideoFile,
    VideoCompressionInsightResult,
)
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Silence noisy loggers
logging.getLogger("subprocess").setLevel(logging.WARNING)


class VideoCompressionInsight(Insight[VideoCompressionInsightResult]):
    """Analyze video compression opportunities in iOS apps.

    Uses FFmpeg to compress video files with H.264 and HEVC encodings to determine optimal compression.
    """

    # Video formats that can be compressed
    COMPRESSIBLE_FORMATS = {"mov", "mp4", "m4v", "avi", "wmv", "3gp", "3g2", "mkv", "webm"}

    # Minimum savings threshold (same as other insights)
    MIN_SAVINGS_THRESHOLD = 4096

    # Compression settings (based on legacy Swift code)
    DEFAULT_QUALITY_FACTOR = 0.85  # 85% of original bitrate
    TARGET_ENCODINGS = ["h264", "hevc"]

    _MAX_WORKERS = 2  # Conservative for video processing (CPU intensive)

    def generate(self, input: InsightsInput) -> VideoCompressionInsightResult | None:
        """Generate video compression insights from file analysis."""
        files = list(self._iter_compressible_files(input.file_analysis.files))
        if not files:
            return None

        results: list[OptimizableVideoFile] = []
        with ThreadPoolExecutor(max_workers=min(self._MAX_WORKERS, len(files))) as executor:
            future_to_file = {executor.submit(self._analyze_video_compression, f): f for f in files}
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

        return VideoCompressionInsightResult(
            optimizable_files=results,
            total_savings=total_savings,
        )

    def _analyze_video_compression(self, file_info: FileInfo) -> OptimizableVideoFile | None:
        """Analyze a single video file for compression opportunities."""
        full_path = file_info.full_path
        if full_path is None:
            logger.debug("Skipping %s because it has no full path", file_info.path)
            return None

        file_size = file_info.size
        file_format = file_info.file_type.lower()

        try:
            # Get video bitrate to calculate target bitrate
            current_bitrate = self._get_video_bitrate(full_path)
            if current_bitrate is None:
                logger.debug("Could not determine bitrate for %s", file_info.path)
                return None

            # Try both H.264 and HEVC encodings to find the best compression
            best_result = None
            for encoding in self.TARGET_ENCODINGS:
                target_bitrate = int(current_bitrate * self.DEFAULT_QUALITY_FACTOR)
                compressed_size = self._get_compressed_size(full_path, encoding, target_bitrate)

                if compressed_size is not None:
                    savings = file_size - compressed_size
                    if savings > 0 and (best_result is None or savings > best_result.potential_savings):
                        best_result = OptimizableVideoFile(
                            file_path=file_info.path,
                            current_size=file_size,
                            current_format=file_format,
                            compressed_size=compressed_size,
                            potential_savings=savings,
                            target_encoding=encoding,
                            target_bitrate=target_bitrate,
                        )

            return best_result

        except Exception as exc:
            logger.error("Failed to analyze video compression for %s: %s", file_info.path, exc)
            return None

    def _get_video_bitrate(self, video_path: Path) -> int | None:
        """Get the video bitrate using FFmpeg probe."""
        try:
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "quiet",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=bit_rate",
                    "-of",
                    "csv=p=0",
                    str(video_path),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                logger.debug("ffprobe failed for %s: %s", video_path, result.stderr.strip())
                return None

            bitrate_str = result.stdout.strip()
            if bitrate_str and bitrate_str != "N/A":
                return int(bitrate_str)
            else:
                logger.debug("No bitrate information available for %s", video_path)
                return None

        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError) as exc:
            logger.debug("Error getting bitrate for %s: %s", video_path, exc)
            return None

    def _get_compressed_size(self, video_path: Path, encoding: str, target_bitrate: int) -> int | None:
        """Get the compressed size using FFmpeg with specified encoding."""
        # Choose output extension based on encoding
        extension = "mp4" if encoding == "h264" else "mov"

        with tempfile.NamedTemporaryFile(suffix=f"-compressed.{extension}", delete=True) as temp_file:
            temp_path = Path(temp_file.name)

            try:
                # Build FFmpeg command based on encoding
                codec = "libx264" if encoding == "h264" else "libx265"
                cmd = [
                    "ffmpeg",
                    "-i",
                    str(video_path),
                    "-c:v",
                    codec,
                    "-b:v",
                    str(target_bitrate),
                    "-c:a",
                    "copy",  # Copy audio stream without re-encoding
                    "-y",  # Overwrite output file
                    str(temp_path),
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,  # Longer timeout for video processing
                    check=False,
                )

                if result.returncode != 0:
                    logger.debug(
                        "ffmpeg failed for %s with %s: %s",
                        video_path,
                        encoding,
                        result.stderr.strip() if result.stderr else "Unknown error",
                    )
                    return None

                if temp_path.exists():
                    return temp_path.stat().st_size
                else:
                    logger.debug("Compressed file not created for %s", video_path)
                    return None

            except subprocess.TimeoutExpired:
                logger.error("ffmpeg timeout for %s with %s encoding", video_path, encoding)
                return None
            except FileNotFoundError:
                logger.error("ffmpeg not found - video compression analysis unavailable")
                return None
            except Exception as exc:
                logger.error("Unexpected error during video compression: %s", exc)
                return None

    def _iter_compressible_files(self, files: Sequence[FileInfo]) -> Iterable[FileInfo]:
        """Iterate through files that can be compressed."""
        for fi in files:
            if self._is_compressible_video_file(fi):
                yield fi

    def _is_compressible_video_file(self, file_info: FileInfo) -> bool:
        """Check if a file is a compressible video format."""
        file_type = file_info.file_type.lower()

        # Check if it's a known compressible video format
        if file_type not in self.COMPRESSIBLE_FORMATS:
            return False

        # Skip very small video files (likely thumbnails or icons)
        if file_info.size < self.MIN_SAVINGS_THRESHOLD * 10:  # At least 40KB
            return False

        return True
