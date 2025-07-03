from pathlib import Path

from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer


class TestLargeFileInsightIntegration:
    def test_large_file_insight_with_hackernews_apk(self):
        """Test large file insight with the HackerNews APK fixture."""
        apk_path = Path("tests/_fixtures/android/hn.apk")

        artifact = ArtifactFactory.from_path(apk_path)
        analyzer = AndroidAnalyzer(skip_insights=False)

        results = analyzer.analyze(artifact)

        assert results.insights is not None
        assert results.insights.large_files is not None

        # The HackerNews APK doesn't have anything larger than 10MB,
        # We check for a valid structure.
        assert results.insights.large_files.total_savings >= 0
