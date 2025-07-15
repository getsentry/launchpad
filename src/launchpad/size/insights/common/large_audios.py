from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import (
    LargeAudioFileInsightResult,
)


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
