from pathlib import Path

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.analyzers.apple import AppleAppAnalyzer


class TestStripSymbolsInsightIntegration:
    def test_strip_symbols_with_hackernews_analyzer(self):
        artifact_path = Path("tests/_fixtures/ios/HackerNews-Debug.xcarchive.zip")

        analyzer = AppleAppAnalyzer(
            skip_swift_metadata=True,
            skip_symbols=True,
            skip_image_analysis=True,
            skip_insights=False,
        )

        artifact = ZippedXCArchive(artifact_path)
        results = analyzer.analyze(artifact)

        assert results is not None
        assert results.app_info is not None
        assert results.file_analysis is not None
        assert results.binary_analysis is not None
        assert len(results.binary_analysis) > 0

        assert results.insights is not None

        strip_insight = results.insights.strip_binary

        print(strip_insight)
        assert strip_insight.total_savings == 97552
        assert len(strip_insight.files) == 2
        assert strip_insight.files[0].size_saved == 85696
        assert strip_insight.files[1].size_saved == 11856
