"""Integration tests for LargeFileInsight with real Android artifacts."""

from pathlib import Path

from launchpad.analyzers.android import AndroidAnalyzer
from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestLargeFileInsightIntegration:
    """Integration tests for LargeFileInsight."""

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
        assert isinstance(results.insights.large_files.large_file_count, int)
        assert isinstance(results.insights.large_files.total_savings, int)
        assert results.insights.large_files.total_savings >= 0

        if results.insights.large_files.files:
            file_sizes = [f.size for f in results.insights.large_files.files]
            assert file_sizes == sorted(file_sizes, reverse=True)

            # Verify all files are actually larger than 10MB
            for file in results.insights.large_files.files:
                assert file.size > 10 * 1024 * 1024  # 10MB
