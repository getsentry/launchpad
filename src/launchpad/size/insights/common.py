"""Base classes for app artifact insights."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    DuplicateFilesInsightResult,
    LargeAudioFileInsightResult,
    LargeImageFileInsightResult,
    LargeVideoFileInsightResult,
)


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    def generate(self, input: InsightsInput) -> DuplicateFilesInsightResult:
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for file in input.file_analysis.files:
            if file.hash_md5:
                files_by_hash[file.hash_md5].append(file)

        duplicate_files: List[FileInfo] = []
        total_savings = 0

        for file_list in files_by_hash.values():
            if len(file_list) > 1:
                total_file_size = sum(f.size for f in file_list)
                savings = total_file_size - file_list[0].size

                if savings > 0:  # Only include if there are actual savings
                    # Add all files except the first one (which we'll keep)
                    duplicate_files.extend(file_list[1:])
                    total_savings += savings

        return DuplicateFilesInsightResult(
            files=duplicate_files,
            total_savings=total_savings,
        )


class LargeImageFileInsight(Insight[LargeImageFileInsightResult]):
    """Insight for identifying image files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeImageFileInsightResult:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB - chosen arbitrarily, we can change this later

        # Android supported image types: https://developer.android.com/media/platform/supported-formats#image-formats
        # Apple supported image types: https://developer.apple.com/library/archive/documentation/2DDrawing/Conceptual/DrawingPrintingiOS/LoadingImages/LoadingImages.html#//apple_ref/doc/uid/TP40010156-CH17-SW7
        image_types = [
            "png",
            "jpg",
            "jpeg",
            "webp",
            "bmp",
            "gif",
            "heif",
            "avif",
            "tif",
            "tiff",
            "ico",
            "heic",
            "cur",
            "xbm",
        ]
        image_files = [file for file in input.file_analysis.files if file.file_type in image_types]

        large_files = [file for file in image_files if file.size > size_threshold_bytes]

        # Sort by largest first
        large_files.sort(key=lambda f: f.size, reverse=True)

        # Calculate total potential savings (assuming files can be optimized to 50% of their size)
        total_savings = sum(file.size // 2 for file in large_files)

        return LargeImageFileInsightResult(files=large_files, total_savings=total_savings)


class LargeVideoFileInsight(Insight[LargeVideoFileInsightResult]):
    """Insight for identifying video files larger than 10MB."""

    def generate(self, input: InsightsInput) -> LargeVideoFileInsightResult:
        size_threshold_bytes = 10 * 1024 * 1024  # 10MB

        # Android supported video types: https://developer.android.com/media/platform/supported-formats#video-formats
        # Apple supported video types: https://stackoverflow.com/questions/1535836/video-file-formats-supported-in-iphone
        video_types = ["mp4", "3gp", "webm", "mkv", "mov", "m4v"]
        video_files = [file for file in input.file_analysis.files if file.file_type in video_types]

        large_files = [file for file in video_files if file.size > size_threshold_bytes]

        # Sort by largest first
        large_files.sort(key=lambda f: f.size, reverse=True)

        # Calculate total potential savings (assuming files can be optimized to 50% of their size)
        total_savings = sum(file.size // 2 for file in large_files)

        return LargeVideoFileInsightResult(files=large_files, total_savings=total_savings)


class LargeAudioFileInsight(Insight[LargeAudioFileInsightResult]):
    """Insight for identifying audio files larger than 5MB."""

    def generate(self, input: InsightsInput) -> LargeAudioFileInsightResult:
        size_threshold_bytes = 5 * 1024 * 1024  # 5MB - chosen arbitrarily, we can change this later

        # Android supported audio types: https://developer.android.com/media/platform/supported-formats#audio-formats
        # Apple supported audio types: https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/SupportedAudioFormatsMacOSX/SupportedAudioFormatsMacOSX.html
        audio_types = [
            "mp3",
            "aac",
            "wav",
            "flac",
            "ogg",
            "m4a",
            "wma",
            "aiff",
            "aif",
            "snd",
            "au",
            "sd2",
            "caf",
        ]
        audio_files = [file for file in input.file_analysis.files if file.file_type in audio_types]

        large_files = [file for file in audio_files if file.size > size_threshold_bytes]

        # Sort by largest first
        large_files.sort(key=lambda f: f.size, reverse=True)

        # Calculate total potential savings (assuming files can be optimized to 50% of their size)
        total_savings = sum(file.size // 2 for file in large_files)

        return LargeAudioFileInsightResult(files=large_files, total_savings=total_savings)
