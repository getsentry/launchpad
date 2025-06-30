from pathlib import Path
from typing import cast

import pytest

from launchpad.artifacts.artifact import AndroidArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.models.android import WebPOptimizationInsightResult


class TestWebPOptimizationInsight:
    @pytest.fixture
    def sample_android_apk_path(self) -> Path:
        return Path("tests/_fixtures/android/hn-with-optimizeable-image.apk")

    def test_webp_optimization_insight_with_apk(self, sample_android_apk_path: Path) -> None:
        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_apk_path)
        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        assert results.insights is not None
        assert results.insights.webp_optimization is not None

        webp_result = results.insights.webp_optimization

        assert isinstance(webp_result, WebPOptimizationInsightResult)
        assert isinstance(webp_result.optimizeable_image_files, list)

        print(webp_result.optimizeable_image_files)
        assert webp_result.optimizeable_image_files[0].file_info.path == "res/07.png"
        assert webp_result.optimizeable_image_files[0].potential_savings == 11536
