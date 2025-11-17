from pathlib import Path
from typing import cast

from launchpad.artifacts.artifact import AndroidArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.models.insights import WebPOptimizationInsightResult


class TestWebPOptimizationInsight:
    def test_webp_optimization_insight_with_apk(self, hn_optimizable_apk: Path) -> None:
        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(hn_optimizable_apk)
        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        assert results.insights is not None
        assert results.insights.webp_optimization is not None

        webp_result = results.insights.webp_optimization

        assert isinstance(webp_result, WebPOptimizationInsightResult)
        assert isinstance(webp_result.files, list)
        assert webp_result.total_savings > 0

        print(webp_result.files)
        assert webp_result.files[0].file_path == "res/07.png"
        assert webp_result.files[0].total_savings == 11536
