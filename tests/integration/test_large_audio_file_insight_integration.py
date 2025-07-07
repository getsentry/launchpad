from pathlib import Path

from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer


class TestLargeAudioFileInsightIntegration:
    def test_large_audio_file_insight_with_hackernews_apk(self):
        """Test large audio file insight with the HackerNews APK fixture."""
        apk_path = Path("tests/_fixtures/android/hn.apk")

        artifact = ArtifactFactory.from_path(apk_path)
        analyzer = AndroidAnalyzer(skip_insights=False)

        results = analyzer.analyze(artifact)

        assert results.insights is not None
        assert results.insights.large_audio is not None

        # The HackerNews APK doesn't have audio files larger than 5MB,
        # so we check for a valid structure with empty results
        assert results.insights.large_audio.total_savings >= 0
        assert isinstance(results.insights.large_audio.files, list)
        assert len(results.insights.large_audio.files) == 0
